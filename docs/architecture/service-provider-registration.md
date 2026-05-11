# Service Provider Registration Workflow

Service provider registration is the setup step that makes a service trusted by XSO. A service must be registered before it can create login challenges, receive browser callbacks, or exchange login result codes for access tokens.

## Scope

The first implementation should expose a backend/admin API. An admin UI can be added later, but browser users and service frontends must not be able to self-register services.

The admin API is a control-plane surface, separate from the browser login flow and separate from future internal gRPC contracts.

## Data Construction

Each registered service provider contains:

- Service provider ID: stable unique identifier used by challenge creation and token exchange.
- Display name: human-readable name shown in admin surfaces and future consent/audit views.
- Allowed return URLs: exact callback URLs that XSO may redirect to after login.
- Active status: disabled services cannot create challenges or exchange login result codes.
- Service secret verifier: password-hash-style verifier for backend-to-backend service authentication.
- Created timestamp: registration creation time.
- Updated timestamp: last metadata or status change time.

The raw service secret is accepted only at registration or rotation time. XSO persists only the verifier and never returns the secret after it has been accepted.

## Registration Workflow

1. An administrator calls `POST /admin/service-providers` with the service provider ID, display name, allowed return URLs, active status, and an initial service secret.
2. XSO authenticates the admin request before reading or persisting the registration payload.
3. XSO normalizes and validates the service provider ID.
4. XSO validates that the display name is present and safe to render.
5. XSO validates every allowed return URL as an absolute HTTPS URL, rejects fragments, and removes duplicate entries.
6. XSO validates the initial service secret according to the configured minimum policy.
7. XSO checks that the service provider ID does not already exist.
8. XSO hashes the service secret with the backend password verifier strategy.
9. XSO persists the service provider metadata and secret verifier in the service provider store.
10. XSO returns non-secret service provider metadata to the administrator.

## Login Challenge Workflow

1. An unauthenticated user reaches a service route.
2. The service backend redirects the browser to XSO with its service provider ID and requested return URL, or calls a future backend challenge API and then redirects to the resulting login URL.
3. XSO loads the registered service provider by ID.
4. XSO verifies the service provider is active.
5. XSO verifies the requested return URL exactly matches one registered allowed return URL.
6. XSO creates a short-lived challenge with challenge ID, service provider ID, return URL, expiration, created timestamp, and CSRF or nonce data.
7. XSO redirects or serves `GET /login?challenge=...`.
8. `GET /login` validates the challenge before serving the Vue login page.

## Login Result Exchange Workflow

1. After successful credential submission, XSO creates an IdP session and a short-lived login result containing a one-time code and a server-side access token.
2. XSO redirects the browser to the registered return URL with only the one-time code.
3. The service backend receives the callback and calls `POST /login/token` with its service provider ID, service secret, and the one-time code.
4. XSO authenticates the service provider with the persisted secret verifier.
5. XSO verifies the code exists, is not expired, is not used, and belongs to the same service provider.
6. XSO marks the code used and returns the access token only to the service backend.

## Rejection Workflow

Registration must reject:

- unauthenticated admin requests;
- missing or duplicate service provider IDs;
- missing display names;
- empty allowed return URL lists;
- invalid return URL syntax;
- non-HTTPS return URLs outside explicit local development exceptions;
- duplicate return URLs;
- weak or missing service secrets;
- persistence conflicts or backend storage failures.

Challenge creation and login access must reject:

- unknown service provider IDs;
- inactive service providers;
- return URLs that do not exactly match a registered URL;
- missing, unknown, expired, or reused challenges;
- direct login page access without a valid challenge.

Token exchange must reject:

- missing service provider credentials;
- unknown, inactive, or incorrectly authenticated service providers;
- unknown, expired, reused, or wrong-audience login result codes;
- requests that would expose access tokens to the browser.

## Edge Cases

- Service provider ID matching should be deterministic. The first implementation should either require lowercase IDs or normalize them before uniqueness checks.
- Return URL matching should stay exact to avoid open redirects. Wildcards, partial host matches, and query-prefix matches are out of scope for the first implementation.
- Service secret rotation should be a separate workflow so old and new secrets can be managed deliberately.
- Disabling a service should immediately block new challenges and token exchanges. Existing IdP sessions may remain valid until separate session revocation exists.
- Registration should produce audit events once the audit model exists, but audit persistence should not leak service secrets.

## Tests First

The backend registration implementation should start with tests for:

- successful registration with persisted metadata and secret verifier;
- duplicate service provider ID rejection;
- missing required fields;
- invalid and duplicate return URLs;
- weak or missing service secret;
- active service can create a login challenge;
- inactive service cannot create a login challenge;
- registered service can exchange its own login result code;
- wrong service cannot exchange another service provider's code;
- service secret is never returned in registration responses.
