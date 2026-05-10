# XSO Todo List

## Current Status

- [x] Repository initialized.
- [x] Project guidance added in `AGENTS.md`.
- [x] Go monorepo scaffold created with `apps/xso-idp`, `apps/sample-client`, and `packages/xso-go`.
- [x] Vue 3 selected for `frontend/xso-login`.
- [x] Basic login frontend scaffold created with Vite + Vue 3.
- [x] TDD rule added: write or update failing tests before production code.
- [x] Edge-case rule added: identify meaningful edge cases and failure modes before implementation.
- [x] Login page access rule added: direct navigation must be rejected by backend validation.

## Active Architecture Decisions

- Login UI is hosted by XSO.
- Login page access requires a valid SSO redirect/challenge.
- Browser-facing login behavior uses HTTP endpoints.
- Internal service validation should use typed backend contracts.
- Authentication logic belongs in backend services, not the Vue frontend.
- The Go SDK should stay framework-agnostic, with `net/http` support as the first adapter.

## Next Work

- [ ] Define the login challenge model.
  - Goal: represent a short-lived login attempt created by XSO after a registered service provider asks XSO to authenticate a user.
  - Creation entry point: a service provider redirects or calls XSO with its service provider ID and requested return URL.
  - Challenge data: challenge ID, service provider ID, return URL, expiration time, used status, created timestamp, optional CSRF token or nonce.
  - Storage workflow: validate service provider and return URL first, create a random unguessable challenge ID, persist the challenge, and expose only the challenge reference to the browser.
  - Validation workflow: load the challenge by ID, verify it exists, verify it is not expired, verify it has not been used, verify the service provider is still active, then allow login page access.
  - Rejection workflow: reject missing challenge, unknown challenge, expired challenge, reused challenge, inactive service provider, and unsafe return URL.
  - Tests first: cover successful challenge creation, missing challenge rejection, expired challenge rejection, reused challenge rejection, unknown service provider rejection, inactive service provider rejection, and invalid return URL rejection.

- [ ] Implement backend route behavior for `GET /login`.
  - Goal: serve the Vue login page only when the request is part of a valid SSO login challenge.
  - Entry point: browser requests `GET /login?challenge=...` after being redirected by XSO or a registered service provider.
  - Request data: challenge ID from query parameter or another backend-approved transport, plus normal browser cookies needed for CSRF/session handling.
  - Validation workflow: parse the challenge reference, validate the challenge model, bind the browser request to the challenge if needed, then serve the login app shell.
  - Success workflow: return the Vue app with enough non-sensitive page context to submit credentials for that challenge.
  - Rejection workflow: direct access to `/login`, missing challenge, invalid challenge, expired challenge, reused challenge, and inactive service provider must be rejected by backend validation.
  - Tests first: cover valid login page access, direct navigation rejection, missing challenge rejection, expired challenge rejection, reused challenge rejection, and inactive service provider rejection.

- [ ] Implement backend route behavior for `POST /login`.
  - Goal: authenticate credentials for a valid challenge, create the appropriate session or assertion state, and return the browser to the registered service provider.
  - Entry point: Vue login form submits credentials to `POST /login` with the active challenge reference.
  - Request data: challenge ID, account identifier, password, CSRF token if cookie-based state is used, and browser cookies needed by the flow.
  - Validation workflow: validate challenge first, validate CSRF protections, verify required credential fields, authenticate the account, load authority information, create session/assertion state, mark challenge as used, then redirect to the validated return URL.
  - Success workflow: set secure server-managed session state or complete the assertion exchange without exposing raw tokens in URLs or browser storage.
  - Rejection workflow: reject missing credentials, invalid credentials, expired challenge, reused challenge, duplicate submission, invalid CSRF token, locked/disabled user, and unsafe redirect target.
  - Tests first: cover successful login, missing credentials rejection, generic invalid credential error, expired challenge rejection, duplicate submission rejection, unsafe redirect rejection, and no account-existence leakage.

- [ ] Define the full service provider registration workflow.
  - Goal: a new service must be registered with XSO before it can send users into the SSO login flow.
  - Registration entry point: start with a backend/admin API such as `POST /admin/service-providers`; add an admin UI later.
  - Registration data: service provider ID, display name, allowed return URLs, active status, created/updated timestamps.
  - Storage workflow: validate registration input, reject duplicate service provider IDs, persist the service provider, and make it available to login challenge validation.
  - Login challenge workflow: service redirects an unauthenticated user to XSO with service provider ID and return target; XSO loads the registered service provider, validates active status, validates the return URL, creates a challenge, then allows the login page to render.
  - Rejection workflow: XSO rejects unknown service providers, inactive service providers, mismatched return URLs, expired challenges, reused challenges, and direct login page access without a challenge.
  - Tests first: cover successful registration, duplicate registration rejection, valid challenge creation, unknown service rejection, inactive service rejection, unsafe return URL rejection, and direct login access rejection.

- [ ] Add frontend tests for login page states.
  - Goal: verify the Vue login page handles user-visible states correctly while leaving all security decisions to backend validation.
  - Test entry point: component tests for `App.vue`, using mocked `fetch` responses and browser APIs.
  - UI states: initial form, client-side missing field validation, submitting/disabled state, invalid credentials, service unavailable, and successful redirect.
  - Data handling workflow: collect identifier and password, submit to the backend with credentials included, clear password after failed authentication, keep identifier for retry, and never write tokens to `localStorage`, `sessionStorage`, or URLs.
  - Accessibility workflow: labels remain associated with inputs, errors use an alert region, and submit state is visible to assistive technology.
  - Rejection workflow: backend failure must show a generic message and must not expose internal error codes, stack traces, or account-existence details.
  - Tests first: cover initial render, required field handling, submit disabled while pending, password clearing after failure, generic error display, successful redirect, and no browser-storage token writes.

- [ ] Replace placeholder SDK session validation with a real interface.
  - Goal: make `packages/xso-go` validate sessions through an explicit backend boundary instead of hardcoded placeholder behavior.
  - SDK entry point: application code creates an XSO client and installs middleware around protected `net/http` routes.
  - Interface data: session credential, request context, validation result, user identity, roles, groups, permissions, and typed validation errors.
  - Validation workflow: middleware extracts session credential, calls the validator/client interface, maps valid results into request context, and passes the request to the next handler.
  - Rejection workflow: missing session, empty session, expired session, invalid token, backend validation failure, timeout, and malformed validator response must become unauthorized responses without leaking internals.
  - Extensibility workflow: keep core validation independent from web frameworks; `net/http` remains the first adapter.
  - Tests first: cover empty session rejection, valid session context injection, expired session rejection, validator error mapping, timeout/error behavior, and framework-independent validator use.

- [ ] Add CI-friendly verification commands.
  - Goal: define one repeatable local and CI verification path for backend, SDK, frontend, and generated assets.
  - Entry point: root-level documentation first; later add scripts or CI workflow files.
  - Go workflow: run `go work sync`, then `go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...`.
  - Frontend workflow: run `npm ci` and `npm run build` from `frontend/xso-login`.
  - Generated asset workflow: when protobuf generation is added, include a check that generated files are up to date.
  - Rejection workflow: CI must fail on Go test failures, frontend type/build failures, missing lockfile consistency, or stale generated files.
  - Tests first: for script changes, add or document a local dry-run command and verify it fails clearly when a required step fails.

## Later Work

- [ ] Add protobuf generation workflow.
  - Goal: generate typed Go code from `proto/xso/auth.proto` without hand-editing generated files.
  - Entry point: documented generation command or script from the repo root.
  - Tooling data: protoc version, Go protobuf plugins, output directories, package names, and generated file ownership.
  - Generation workflow: install or document required tools, run generation, write generated files to the expected Go package path, and include generated files in verification.
  - Rejection workflow: fail when protoc/plugins are missing, generated code is stale, package paths do not match module paths, or generated files are manually edited.
  - Tests first: add a verification step that detects stale generated protobuf output.

- [ ] Add PostgreSQL schema draft for users, sessions, service providers, roles, and permissions.
  - Goal: define the first durable data model for authentication, service registration, sessions, and authorization.
  - Entry point: SQL migration files or schema docs before wiring runtime database access.
  - Schema data: users, credentials, sessions, service providers, allowed return URLs, roles, permissions, user-role links, role-permission links, and audit-relevant timestamps.
  - Migration workflow: create tables with primary keys, unique constraints, foreign keys, indexes, and explicit nullable fields.
  - Rejection workflow: reject duplicate users, duplicate service provider IDs, duplicate allowed return URLs per service, invalid foreign keys, and dangling role/permission links.
  - Tests first: when migrations are executable, cover migration up/down behavior and important uniqueness/foreign-key constraints.

- [ ] Add Redis-backed challenge/session cache design.
  - Goal: support short-lived login challenges, replay protection, session cache, and rate-limit counters without making the database the only hot path.
  - Entry point: cache interface design before introducing a Redis client dependency.
  - Cache data: challenge IDs, used challenge markers, session validation cache entries, replay-prevention nonces, and rate-limit counters.
  - Cache workflow: write challenge/session entries with TTLs, read before database fallback where appropriate, atomically mark one-time challenge use, and expire sensitive state automatically.
  - Rejection workflow: handle cache miss, expired keys, duplicate challenge use, Redis timeout, Redis outage, and inconsistent cache/database state.
  - Tests first: use an interface-backed fake cache to cover TTL behavior, one-time-use behavior, cache miss fallback, and Redis failure fallback rules.

- [ ] Add audit event model for login success, login failure, challenge rejection, and logout.
  - Goal: record security-relevant events consistently for debugging, abuse detection, and future compliance work.
  - Entry point: backend audit package or interface used by login and challenge flows.
  - Event data: event ID, event type, timestamp, service provider ID, user ID when known, challenge ID when available, request metadata, result, and reason code.
  - Audit workflow: emit events for challenge creation, challenge rejection, login success, login failure, logout, service provider registration, and service provider disablement.
  - Rejection workflow: audit failures must not expose sensitive details to users; decide whether critical audit write failures block security-sensitive actions.
  - Tests first: cover emitted event type/reason for success and failure paths, ensure passwords/tokens are never logged, and verify generic login failures still produce useful reason codes.

- [ ] Add Docker Compose services for app, database, and Redis.
  - Goal: provide a repeatable local environment for XSO, PostgreSQL, Redis, and sample service development.
  - Entry point: `deploy/docker-compose.yml` and related Dockerfiles or environment examples.
  - Service data: container names, ports, health checks, environment variables, volumes, and network names.
  - Startup workflow: build app images, start PostgreSQL and Redis, wait for health checks, run migrations when they exist, then start app services.
  - Rejection workflow: fail clearly on missing environment variables, port conflicts, database readiness failures, Redis readiness failures, and migration failures.
  - Tests first: add a lightweight compose validation command or documented smoke test once services are wired.

- [ ] Add docs for authentication flow and threat model.
  - Goal: document how the XSO login flow works and which security threats the design handles or explicitly defers.
  - Entry point: docs under `docs/architecture` or `docs/backend`.
  - Flow content: service provider registration, login challenge creation, login page access, credential submission, session/assertion creation, callback/return handling, logout, and failure paths.
  - Threat model content: direct login access, open redirects, replayed challenges, credential enumeration, CSRF, token leakage, session fixation, insecure cookies, and audit gaps.
  - Review workflow: keep docs aligned with tests and implementation whenever authentication behavior changes.
  - Tests first: not applicable for prose, but docs should reference the tests or verification commands that enforce key security rules.
