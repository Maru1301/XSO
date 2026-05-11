# Redis-Backed Challenge and Session Cache Design

This draft defines how XSO should use Redis for short-lived authentication state without making Redis the source of truth for durable identity, service provider registration, or authorization data.

Redis should be introduced behind an interface first. The initial implementation can keep in-memory fakes for tests and add a real Redis client only when runtime wiring needs it.

## Scope

Redis owns hot, short-lived, and replay-sensitive state:

- login challenge lookup;
- one-time challenge consumption markers;
- IdP session validation cache entries;
- login result code replay markers;
- CSRF or nonce replay markers;
- rate-limit counters for login and token exchange.

PostgreSQL remains the durable system of record for users, service providers, sessions, login result metadata, roles, permissions, and audit-relevant records.

## Key Model

Use namespaced keys with explicit versioning so future schema changes can coexist during deployment.

```text
xso:v1:challenge:{challenge_id}
xso:v1:challenge-used:{challenge_id}
xso:v1:session:{session_hash}
xso:v1:login-result-used:{code_hash}
xso:v1:csrf:{challenge_id}:{csrf_hash}
xso:v1:rate:login:{service_provider_id}:{identifier_hash}:{window}
xso:v1:rate:login-ip:{ip_hash}:{window}
xso:v1:rate:token:{service_provider_id}:{window}
```

Key data should be JSON or Redis hashes with stable field names. Token-like values must be stored as hashes, not raw cookie values, callback codes, access tokens, passwords, or service secrets.

## Data Construction

Challenge cache entries contain:

- challenge ID;
- service provider ID;
- return URL;
- CSRF token hash or nonce hash;
- created timestamp;
- expiration timestamp.

Session cache entries contain:

- session hash;
- user ID;
- display name;
- service-independent roles, groups, and permissions needed for SDK validation;
- absolute expiration timestamp;
- idle expiration timestamp;
- last-seen timestamp;
- revocation version or session version when durable revocation exists.

Replay marker entries contain:

- consumed object hash or ID;
- consumed timestamp;
- service provider ID when applicable.

Rate-limit entries contain only counters, first-seen timestamp, and expiry. Identifiers and IP addresses must be hashed before entering Redis.

## TTL Policy

- Challenges: 5 minutes by default, matching the challenge expiration time.
- Challenge used markers: at least the original challenge lifetime plus a small clock-skew buffer.
- Sessions: no longer than the earlier of absolute session expiry and idle expiry. The current IdP design uses an 8-hour absolute lifetime and 30-minute idle lifetime.
- Login result used markers: at least the login result code lifetime plus a small clock-skew buffer.
- CSRF or nonce markers: same TTL as the challenge.
- Login rate limits: short rolling windows, such as 1 minute and 15 minutes, with policy owned by the login service.
- Token exchange rate limits: short rolling windows per service provider.

The application must pass TTLs explicitly. Redis keys containing sensitive authentication state must not be written without an expiration.

## Challenge Workflow

1. XSO validates the service provider and exact return URL against durable storage.
2. XSO creates an unguessable challenge ID and CSRF or nonce value.
3. XSO writes the challenge to Redis with a TTL matching `expires_at`.
4. `GET /login` reads the challenge from Redis first.
5. On cache miss, XSO may fall back to PostgreSQL if durable challenge storage exists.
6. XSO rejects missing, expired, used, or malformed challenge data.
7. `POST /login` atomically consumes the challenge before or during successful login completion.

Challenge consumption should be atomic. A Redis implementation should use `SET key value NX EX ...` for the used marker or a Lua script that verifies the challenge exists, verifies the used marker does not exist, and sets the used marker in one operation.

## Session Workflow

1. Successful login creates the durable session record and an opaque cookie value.
2. XSO stores only a session hash in PostgreSQL and Redis.
3. XSO writes a Redis session validation entry with TTL no longer than the idle expiry.
4. Service session validation checks Redis first for active session data.
5. On cache hit, XSO verifies absolute expiry, idle expiry, and revocation metadata before accepting the session.
6. On cache miss, XSO loads durable session state from PostgreSQL and repopulates Redis if the session is still valid.
7. Logout or administrative revocation deletes the Redis session key and updates durable revocation state.

Idle extension must be deliberate. The validator may refresh Redis TTL after a successful validation, but it should also persist or periodically flush `last_seen_at` so a Redis restart does not incorrectly extend stale sessions.

## Login Result Replay Workflow

1. After login, the browser receives only a one-time callback code.
2. The service backend calls XSO to exchange the code.
3. XSO authenticates the service provider first.
4. XSO checks the Redis used marker for the hashed code.
5. XSO validates durable login result metadata and audience.
6. XSO atomically marks the code used and returns the access token only to the service backend.
7. Replayed code exchange attempts are rejected even if durable state has not yet been updated.

Durable state must still record `used_at`. Redis provides fast replay protection, not the audit trail.

## Rate-Limit Workflow

1. Login attempts increment service-provider and identifier-scoped counters.
2. Login attempts also increment IP-scoped counters for abuse detection.
3. Token exchange attempts increment service-provider-scoped counters.
4. Counters are created with expirations and never store raw identifiers or IP addresses.
5. A request exceeding policy is rejected with a generic rate-limit response.

Rate limiting must not create account-existence leaks. Unknown users and known users should exercise the same visible flow and response shape.

## Failure Behavior

- Cache miss: treat as normal and use durable fallback where available.
- Expired key: treat as missing and reject if no valid durable fallback exists.
- Redis timeout: fail closed for challenge consumption and login result replay checks; fail open only for non-critical session validation cache reads when durable fallback succeeds.
- Redis outage: keep login safe by relying on durable storage when atomic replay guarantees can still be enforced there. If atomic replay cannot be enforced, reject the security-sensitive operation.
- Inconsistent Redis/PostgreSQL state: durable revocation, expiration, service provider active status, and user disabled or locked state win over cached data.
- Partial writes: do not expose success to the browser until required durable writes and required replay markers have succeeded.

## Interface Targets

The first Go interface should be behavior-oriented, not Redis-command-oriented:

```go
type ChallengeCache interface {
    StoreChallenge(ctx context.Context, challenge CachedChallenge, ttl time.Duration) error
    LoadChallenge(ctx context.Context, id string) (CachedChallenge, error)
    ConsumeChallenge(ctx context.Context, id string, ttl time.Duration) error
}

type SessionCache interface {
    StoreSession(ctx context.Context, session CachedSession, ttl time.Duration) error
    LoadSession(ctx context.Context, sessionHash []byte) (CachedSession, error)
    DeleteSession(ctx context.Context, sessionHash []byte) error
}

type ReplayCache interface {
    MarkUsed(ctx context.Context, namespace string, digest []byte, ttl time.Duration) error
}

type RateLimiter interface {
    Increment(ctx context.Context, key RateLimitKey, ttl time.Duration) (RateLimitState, error)
}
```

The interfaces should return typed errors for cache miss, already used, rate limited, timeout, and unavailable. HTTP handlers should translate those errors into generic browser-facing responses.

## Edge Cases

- Every sensitive key must have a TTL.
- Challenge consumption and login result code consumption must be atomic.
- Clock skew should be handled by storing explicit expiration timestamps in values and by using TTL buffers for used markers.
- Redis must never store raw passwords, raw session cookies, raw callback codes, raw access tokens, or raw service secrets.
- Session cache entries can become stale after user disablement, lockout, role changes, service disablement, or admin revocation. Durable revocation versioning or short TTLs should limit stale authorization.
- Redis cluster deployments require key tags if multi-key atomic scripts are used.
- Rate-limit keys must avoid raw personal data and must not create different visible responses for unknown versus known accounts.
- Local development can use in-memory cache implementations, but tests should exercise the same interface semantics expected from Redis.

## Test Targets

Before adding a real Redis client, interface-backed tests should cover:

- challenge store/load with TTL;
- challenge miss after expiry;
- atomic challenge consume success;
- duplicate challenge consume rejection;
- session cache hit;
- session cache miss fallback behavior;
- session deletion after logout;
- login result replay marker success;
- duplicate login result replay marker rejection;
- rate-limit counter increment and expiry;
- Redis timeout mapping for challenge consume;
- Redis outage fallback for session read with durable session success;
- fail-closed behavior when replay protection cannot be guaranteed.
