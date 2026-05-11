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
- [x] Backend `POST /login` route behavior implemented behind explicit authenticator and session issuer interfaces.
- [x] Concrete in-memory credential verification and IdP session/login-result code backend added.
- [x] Backend login-result code exchange endpoint added for service backends.
- [x] Full service provider registration workflow defined in `docs/architecture/service-provider-registration.md`.
- [x] Backend admin service provider registration implemented with in-memory storage.
- [x] SDK placeholder session validation replaced with an explicit validator interface.
- [x] CI-friendly verification command added.

## Active Architecture Decisions

- Login UI is hosted by XSO.
- Login page access requires a valid SSO redirect/challenge.
- Browser-facing login behavior uses HTTP endpoints.
- Internal service validation should use typed backend contracts.
- Authentication logic belongs in backend services, not the Vue frontend.
- The Go SDK should stay framework-agnostic, with `net/http` support as the first adapter.

## Next Work

- [x] Define the login challenge model.
  - Goal: represent a short-lived login attempt created by XSO after a registered service provider asks XSO to authenticate a user.
  - Creation entry point: a service provider redirects or calls XSO with its service provider ID and requested return URL.
  - Challenge data: challenge ID, service provider ID, return URL, expiration time, used status, created timestamp, optional CSRF token or nonce.
  - Storage workflow: validate service provider and return URL first, create a random unguessable challenge ID, persist the challenge, and expose only the challenge reference to the browser.
  - Validation workflow: load the challenge by ID, verify it exists, verify it is not expired, verify it has not been used, verify the service provider is still active, then allow login page access.
  - Rejection workflow: reject missing challenge, unknown challenge, expired challenge, reused challenge, inactive service provider, and unsafe return URL.
  - Tests first: cover successful challenge creation, missing challenge rejection, expired challenge rejection, reused challenge rejection, unknown service provider rejection, inactive service provider rejection, and invalid return URL rejection.

- [x] Implement backend route behavior for `GET /login`.
  - Goal: serve the Vue login page only when the request is part of a valid SSO login challenge.
  - Entry point: browser requests `GET /login?challenge=...` after being redirected by XSO or a registered service provider.
  - Request data: challenge ID from query parameter or another backend-approved transport, plus normal browser cookies needed for CSRF/session handling.
  - Validation workflow: parse the challenge reference, validate the challenge model, bind the browser request to the challenge if needed, then serve the login app shell.
  - Success workflow: return the Vue app with enough non-sensitive page context to submit credentials for that challenge.
  - Rejection workflow: direct access to `/login`, missing challenge, invalid challenge, expired challenge, reused challenge, and inactive service provider must be rejected by backend validation.
  - Tests first: cover valid login page access, direct navigation rejection, missing challenge rejection, expired challenge rejection, reused challenge rejection, and inactive service provider rejection.

- [x] Implement backend route behavior for `POST /login`.
  - Goal: authenticate credentials for a valid challenge, create the appropriate session or assertion state, and return the browser to the registered service provider.
  - Entry point: Vue login form submits credentials to `POST /login` with the active challenge reference.
  - Request data: challenge ID, account identifier, password, CSRF token if cookie-based state is used, and browser cookies needed by the flow.
  - Validation workflow: validate challenge first, validate CSRF protections, verify required credential fields, authenticate the account, load authority information, create session/assertion state, mark challenge as used, then redirect to the validated return URL.
  - Success workflow: set secure server-managed session state or complete the assertion exchange without exposing raw tokens in URLs or browser storage.
  - Rejection workflow: reject missing credentials, invalid credentials, expired challenge, reused challenge, duplicate submission, invalid CSRF token, locked/disabled user, and unsafe redirect target.
  - Tests first: cover successful login, missing credentials rejection, generic invalid credential error, expired challenge rejection, duplicate submission rejection, unsafe redirect rejection, and no account-existence leakage.
  - Implemented route workflow: `POST /login` accepts JSON credentials, validates the challenge, delegates credential verification to a backend authenticator interface, delegates session/assertion creation to a backend session issuer interface, marks the challenge as used, sets issuer-provided cookies, and returns a backend-validated `redirectUrl` for the Vue page to navigate to.
  - Implemented rejection behavior: malformed JSON and missing fields return generic request errors, invalid or disabled users return a generic unauthorized error without account-existence leakage, expired or reused challenges are rejected by challenge validation, and unexpected backend failures return server errors.
  - Remaining implementation dependency: real credential storage, CSRF binding, and durable session/assertion issuance still need their own data model and backend implementations before production login can succeed outside tests.

- [x] Implement concrete credential and session backend.
  - Goal: replace the current `POST /login` test doubles and unconfigured runtime wiring with a real backend-owned authentication and session/assertion implementation.
  - Entry point: provide concrete implementations of the login authenticator and session issuer interfaces used by `POST /login`.
  - Data construction: user ID, account identifiers, password verifier metadata, disabled/locked status, session ID or assertion ID, service provider ID, challenge ID, expiration timestamp, issued-at timestamp, and secure cookie attributes.
  - Authentication workflow: look up the account by normalized identifier, verify the password using a password hashing strategy, reject disabled or locked users, avoid account-existence leakage, and return a stable backend user identity.
  - Session workflow: create a server-managed session or assertion record, bind it to the authenticated user and service provider, set secure `HttpOnly` cookie state when applicable, and expose only the redirect target needed by the browser.
  - Rejection workflow: reject missing users, invalid password, disabled user, locked user, expired challenge, duplicate challenge use, session persistence failure, and unsafe redirect targets with generic browser-facing errors.
  - Tests first: cover valid credential authentication, generic invalid credential behavior, disabled/locked users, password verifier failure, secure cookie attributes, session persistence failure, and no token leakage in JSON responses or browser storage.
  - Implemented credential workflow: in-memory user accounts support multiple normalized identifiers, PBKDF2-SHA256 password verification, disabled-user rejection, locked-user rejection, and generic invalid-credential errors for both unknown accounts and bad passwords.
  - Implemented IdP session workflow: successful login creates an opaque server-side IdP session with an 8-hour absolute lifetime, 30-minute idle expiry metadata, and a secure `HttpOnly` `SameSite=Lax` cookie.
  - Implemented login-result workflow: successful login creates a short-lived opaque access token server-side and returns only a one-time `code` in the browser redirect URL. The access token is exchanged by backend code through the login-result exchange API and is not exposed to the Vue page, JSON response, local storage, or callback URL.
  - Remaining implementation dependency: the current stores are in-memory and the runtime authenticator has no configured users yet. Durable user/session/login-result storage and an HTTP or gRPC code-exchange endpoint still need to be added.

- [x] Add backend login-result code exchange endpoint.
  - Goal: let a registered service backend exchange the browser callback `code` for the server-side access token created by XSO.
  - Entry point: service backend calls XSO after receiving the user callback with `code`.
  - Request data: service provider identity, one-time code, and service authentication material once service registration credentials exist.
  - Exchange workflow: authenticate the service provider, load the login result by code, verify it exists, verify it is not expired, verify it is not used, verify the audience matches the service provider, mark the code as used atomically, and return the access token only to the service backend.
  - Rejection workflow: reject missing code, unknown code, expired code, reused code, wrong service provider, inactive service provider, and unauthenticated service callers without leaking token material.
  - Tests first: cover successful exchange, missing/unknown code rejection, expired code rejection, replay rejection, wrong audience rejection, inactive service rejection, and no access token in browser-facing responses.
  - Implemented endpoint: `POST /login/token` accepts service provider ID, service secret, and one-time code from a service backend.
  - Implemented service authentication workflow: service providers use backend-owned secret verification; unknown services, inactive services, and bad secrets are rejected with generic unauthorized errors.
  - Implemented audience workflow: codes can only be exchanged by the service provider they were issued for, and wrong-audience attempts do not consume the code.
  - Implemented token response workflow: successful exchange marks the code as used and returns the access token only in the backend token response, with `tokenType` and `expiresIn`.
  - Remaining implementation dependency: service provider registration still needs to create and persist service secrets; current runtime stores are in-memory and empty until registration/configuration is added.

- [x] Define the full service provider registration workflow.
  - Goal: a new service must be registered with XSO before it can send users into the SSO login flow.
  - Workflow document: `docs/architecture/service-provider-registration.md`.
  - Registration entry point: start with backend/admin API `POST /admin/service-providers`; add an admin UI later. Browser users and service frontends must not self-register services.
  - Admin boundary: the registration endpoint is a control-plane API and must authenticate the administrator before reading or persisting registration data.
  - Data construction: service provider ID, display name, allowed return URLs, active status, service secret verifier, created timestamp, and updated timestamp.
  - Secret workflow: accept the raw service secret only during registration or future rotation, hash it with the backend password verifier strategy, persist only the verifier, and never return the raw secret in API responses.
  - Registration validation workflow: normalize or strictly validate the service provider ID, require a display name, require at least one allowed return URL, reject invalid or duplicate return URLs, require a strong service secret, reject duplicate service provider IDs, then persist the service provider record.
  - Storage workflow: persist the service provider so challenge creation and service-provider authentication both read the same source of truth.
  - Login challenge workflow: service redirects an unauthenticated user to XSO with service provider ID and return target, or calls a future backend challenge API; XSO loads the registered service provider, validates active status, validates exact return URL match, creates a short-lived challenge, then allows `GET /login?challenge=...` to render.
  - Login result workflow: after successful login, XSO redirects the browser back with only a one-time code; the service backend calls `POST /login/token` with service provider ID, service secret, and code; XSO authenticates the service, verifies audience and replay state, marks the code used, and returns the access token only to the service backend.
  - Rejection workflow: reject unauthenticated admin requests, duplicate service IDs, missing data, invalid return URLs, weak secrets, unknown services, inactive services, mismatched return URLs, expired or reused challenges, direct login access without a challenge, wrong-audience code exchange, and token exposure to browser-facing responses.
  - Edge cases: service provider ID normalization, exact return URL matching, secret rotation as a separate workflow, immediate challenge/exchange blocking after service disablement, and future audit events without secret leakage.
  - Tests first for implementation: cover successful registration, duplicate registration rejection, missing fields, invalid and duplicate return URLs, weak secret rejection, active service challenge creation, inactive service challenge rejection, own-code exchange, wrong-service exchange rejection, and no secret in responses.

- [x] Implement backend admin service provider registration.
  - Goal: convert the defined workflow into backend-owned registration code that populates the service provider store used by challenge creation and token exchange.
  - Entry point: `POST /admin/service-providers` in `apps/xso-idp`, protected by an explicit admin authentication boundary.
  - Request data: service provider ID, display name, allowed return URLs, active status, and initial service secret.
  - Response data: service provider ID, display name, normalized allowed return URLs, active status, created timestamp, and updated timestamp. The raw secret and secret verifier must not be returned.
  - Store changes: add a save/register operation to the service provider store while preserving duplicate-ID protection.
  - Hashing workflow: generate a unique salt for each service secret, create the PBKDF2-SHA256 verifier, persist verifier bytes only, and make `POST /login/token` authenticate against that verifier.
  - Admin validation workflow: authenticate admin request first, reject malformed JSON, reject missing fields, reject duplicate IDs, reject invalid return URLs, reject weak secrets, and map failures to non-leaky HTTP responses.
  - Runtime wiring: create registered services through the admin endpoint so `CreateChallenge`, `GET /login`, `POST /login`, and `POST /login/token` all operate from shared provider data.
  - Tests first: add failing tests for registration success, duplicate ID, invalid URL, weak secret, secret non-disclosure, registered-service challenge creation, and token exchange using the registered secret.
  - Implemented service workflow: `ServiceProviderRegistrationService` validates lowercase-style service IDs, display names, exact HTTPS return URLs, duplicate return URLs, and minimum service secret length before hashing the secret and storing the provider.
  - Implemented admin route: `POST /admin/service-providers` requires `Authorization: Bearer <token>` checked by `StaticAdminAuthenticator`; runtime token comes from `XSO_ADMIN_TOKEN`.
  - Implemented response behavior: success returns metadata only and never returns the raw service secret or verifier.
  - Implemented store integration: `MemoryServiceProviderStore` now registers providers with duplicate-ID protection, and the same store backs challenge validation and service-provider token exchange authentication.
  - Remaining implementation dependency: registration is still in-memory and uses a static admin token. Durable provider storage, service-secret rotation, admin-user authorization, and audit events remain future work.

- [x] Add frontend tests for login page states.
  - Goal: verify the Vue login page handles user-visible states correctly while leaving all security decisions to backend validation.
  - Test entry point: component tests for `App.vue`, using mocked `fetch` responses and browser APIs.
  - UI states: initial form, client-side missing field validation, submitting/disabled state, invalid credentials, service unavailable, and successful redirect.
  - Data handling workflow: collect identifier and password, submit to the backend with credentials included, clear password after failed authentication, keep identifier for retry, and never write tokens to `localStorage`, `sessionStorage`, or URLs.
  - Accessibility workflow: labels remain associated with inputs, errors use an alert region, and submit state is visible to assistive technology.
  - Rejection workflow: backend failure must show a generic message and must not expose internal error codes, stack traces, or account-existence details.
  - Tests first: cover initial render, required field handling, submit disabled while pending, password clearing after failure, generic error display, successful redirect, and no browser-storage token writes.
  - Implemented test runner: added Vitest, Vue Test Utils, jsdom, and `npm run test` for `frontend/xso-login`.
  - Implemented coverage: tests verify initial render, required-field validation without backend calls, pending disabled state, trimmed identifier submission with challenge ID and `credentials: include`, password clearing after invalid credentials, generic network/service error, redirect to backend-provided URL, missing redirect URL handling, and no writes to browser storage.
  - Verification: `npm run test` and `npm run build` pass from `frontend/xso-login`.

- [x] Replace placeholder SDK session validation with a real interface.
  - Goal: make `packages/xso-go` validate sessions through an explicit backend boundary instead of hardcoded placeholder behavior.
  - SDK entry point: application code creates an XSO client and installs middleware around protected `net/http` routes.
  - Interface data: session credential, request context, validation result, user identity, roles, groups, permissions, and typed validation errors.
  - Validation workflow: middleware extracts session credential, calls the validator/client interface, maps valid results into request context, and passes the request to the next handler.
  - Rejection workflow: missing session, empty session, expired session, invalid token, backend validation failure, timeout, and malformed validator response must become unauthorized responses without leaking internals.
  - Extensibility workflow: keep core validation independent from web frameworks; `net/http` remains the first adapter.
  - Tests first: cover empty session rejection, valid session context injection, expired session rejection, validator error mapping, timeout/error behavior, and framework-independent validator use.
  - Implemented SDK interface: `session.Validator` accepts a typed `session.Credential` and returns `session.ValidationResult`; `session.ValidatorFunc` supports lightweight adapters.
  - Implemented client wiring: `xso.NewClient` accepts `xso.WithSessionValidator`, applies configured validation timeout, rejects empty session credentials, rejects missing validators, and rejects malformed validator results without creating a fake local user.
  - Implemented context data: validated users now include roles, groups, and permissions before middleware stores them in request context.
  - Implemented middleware behavior: missing or empty cookies, expired sessions, invalid tokens, backend failures, and timeouts all become generic `401 unauthorized` responses.
  - Sample client update: the sample app now injects its own local development validator instead of relying on SDK placeholder behavior.
  - Verification: SDK tests cover empty session rejection, valid context injection, typed validation errors, timeout behavior, malformed validator results, and framework-independent validator use.

- [x] Add CI-friendly verification commands.
  - Goal: define one repeatable local and CI verification path for backend, SDK, frontend, and generated assets.
  - Entry point: root-level documentation first; later add scripts or CI workflow files.
  - Go workflow: run `go work sync`, then `go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...`.
  - Frontend workflow: run `npm ci` and `npm run build` from `frontend/xso-login`.
  - Generated asset workflow: when protobuf generation is added, include a check that generated files are up to date.
  - Rejection workflow: CI must fail on Go test failures, frontend type/build failures, missing lockfile consistency, or stale generated files.
  - Tests first: for script changes, add or document a local dry-run command and verify it fails clearly when a required step fails.
  - Implemented command: `./scripts/verify.ps1` runs Go workspace sync, Go tests, frontend lockfile install, frontend tests, and frontend production build.
  - Implemented local fast path: `./scripts/verify.ps1 -SkipFrontendInstall` skips `npm ci` for repeated local runs after dependencies are already installed.
  - Documentation: `README.md`, `AGENTS.md`, and `docs/development/verification.md` now point to the verification command and focused backend/frontend alternatives.
  - Generated asset status: the script reports that generated protobuf checks are not configured yet; when protobuf generation is added, stale generated files should become a failing check.

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
