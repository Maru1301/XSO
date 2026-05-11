# PostgreSQL Schema Draft

This draft defines the first durable relational model for XSO identity, service provider registration, IdP sessions, roles, and permissions. It is intentionally schema-first documentation, not an executable migration yet.

The draft assumes PostgreSQL and uses UUID primary keys. A future migration should enable `pgcrypto` or replace `gen_random_uuid()` with application-generated UUIDs.

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name TEXT NOT NULL,
    primary_email TEXT,
    disabled_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_display_name_not_blank CHECK (btrim(display_name) <> ''),
    CONSTRAINT users_primary_email_not_blank CHECK (
        primary_email IS NULL OR btrim(primary_email) <> ''
    )
);

CREATE UNIQUE INDEX users_primary_email_unique
    ON users (lower(primary_email))
    WHERE primary_email IS NOT NULL;

CREATE TABLE user_identifiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identifier_type TEXT NOT NULL,
    normalized_identifier TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT user_identifiers_type_not_blank CHECK (btrim(identifier_type) <> ''),
    CONSTRAINT user_identifiers_identifier_not_blank CHECK (btrim(normalized_identifier) <> ''),
    CONSTRAINT user_identifiers_type_supported CHECK (
        identifier_type IN ('email', 'username', 'employee_id')
    ),
    CONSTRAINT user_identifiers_unique_identifier UNIQUE (identifier_type, normalized_identifier)
);

CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL DEFAULT 'password',
    password_algorithm TEXT NOT NULL,
    password_salt BYTEA NOT NULL,
    password_iterations INTEGER NOT NULL,
    password_key BYTEA NOT NULL,
    rotated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT user_credentials_type_supported CHECK (credential_type IN ('password')),
    CONSTRAINT user_credentials_algorithm_not_blank CHECK (btrim(password_algorithm) <> ''),
    CONSTRAINT user_credentials_iterations_positive CHECK (password_iterations > 0),
    CONSTRAINT user_credentials_salt_not_empty CHECK (length(password_salt) > 0),
    CONSTRAINT user_credentials_key_not_empty CHECK (length(password_key) > 0)
);

CREATE UNIQUE INDEX user_credentials_one_password_per_user
    ON user_credentials (user_id)
    WHERE credential_type = 'password';

CREATE TABLE service_providers (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    secret_algorithm TEXT NOT NULL,
    secret_salt BYTEA NOT NULL,
    secret_iterations INTEGER NOT NULL,
    secret_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT service_providers_id_format CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    CONSTRAINT service_providers_display_name_not_blank CHECK (btrim(display_name) <> ''),
    CONSTRAINT service_providers_secret_algorithm_not_blank CHECK (btrim(secret_algorithm) <> ''),
    CONSTRAINT service_providers_secret_iterations_positive CHECK (secret_iterations > 0),
    CONSTRAINT service_providers_secret_salt_not_empty CHECK (length(secret_salt) > 0),
    CONSTRAINT service_providers_secret_key_not_empty CHECK (length(secret_key) > 0)
);

CREATE TABLE service_provider_return_urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_provider_id TEXT NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    return_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT service_provider_return_urls_url_not_blank CHECK (btrim(return_url) <> ''),
    CONSTRAINT service_provider_return_urls_https CHECK (return_url LIKE 'https://%'),
    CONSTRAINT service_provider_return_urls_unique_per_service UNIQUE (
        service_provider_id,
        return_url
    )
);

CREATE TABLE login_challenges (
    id TEXT PRIMARY KEY,
    service_provider_id TEXT NOT NULL REFERENCES service_providers(id) ON DELETE RESTRICT,
    return_url TEXT NOT NULL,
    csrf_token_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT login_challenges_id_not_blank CHECK (btrim(id) <> ''),
    CONSTRAINT login_challenges_return_url_not_blank CHECK (btrim(return_url) <> ''),
    CONSTRAINT login_challenges_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX login_challenges_service_provider_created_idx
    ON login_challenges (service_provider_id, created_at DESC);

CREATE INDEX login_challenges_expiry_idx
    ON login_challenges (expires_at);

CREATE TABLE idp_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT idp_sessions_hash_not_empty CHECK (btrim(session_hash) <> ''),
    CONSTRAINT idp_sessions_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT idp_sessions_idle_expiry_after_creation CHECK (idle_expires_at > created_at)
);

CREATE INDEX idp_sessions_user_idx
    ON idp_sessions (user_id, created_at DESC);

CREATE INDEX idp_sessions_expiry_idx
    ON idp_sessions (expires_at);

CREATE TABLE login_result_codes (
    code_hash TEXT PRIMARY KEY,
    service_provider_id TEXT NOT NULL REFERENCES service_providers(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL REFERENCES idp_sessions(session_hash) ON DELETE CASCADE,
    access_token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,

    CONSTRAINT login_result_codes_code_hash_not_empty CHECK (btrim(code_hash) <> ''),
    CONSTRAINT login_result_codes_token_hash_not_empty CHECK (btrim(access_token_hash) <> ''),
    CONSTRAINT login_result_codes_expiry_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX login_result_codes_service_provider_idx
    ON login_result_codes (service_provider_id, issued_at DESC);

CREATE INDEX login_result_codes_expiry_idx
    ON login_result_codes (expires_at);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_provider_id TEXT REFERENCES service_providers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT roles_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT roles_display_name_not_blank CHECK (btrim(display_name) <> ''),
    CONSTRAINT roles_name_format CHECK (name ~ '^[a-z0-9][a-z0-9:_-]{1,126}$'),
    CONSTRAINT roles_unique_name_per_scope UNIQUE (service_provider_id, name)
);

CREATE UNIQUE INDEX roles_global_name_unique
    ON roles (name)
    WHERE service_provider_id IS NULL;

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_provider_id TEXT REFERENCES service_providers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT permissions_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT permissions_display_name_not_blank CHECK (btrim(display_name) <> ''),
    CONSTRAINT permissions_name_format CHECK (name ~ '^[a-z0-9][a-z0-9:._-]{1,126}$'),
    CONSTRAINT permissions_unique_name_per_scope UNIQUE (service_provider_id, name)
);

CREATE UNIQUE INDEX permissions_global_name_unique
    ON permissions (name)
    WHERE service_provider_id IS NULL;

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_idx
    ON user_roles (role_id);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX role_permissions_permission_idx
    ON role_permissions (permission_id);
```

## Workflow

1. User accounts are created with a stable `users.id`.
2. Login identifiers are stored in `user_identifiers` after application-side normalization, so email, username, and employee ID lookup can share the same credential workflow.
3. Password verifiers are stored in `user_credentials`; raw passwords are never persisted.
4. Service providers are registered in `service_providers` with a password-hash-style secret verifier.
5. Exact callback targets are stored in `service_provider_return_urls`; challenge creation must verify the requested return URL against this table before creating a challenge.
6. `login_challenges` records short-lived browser login attempts and supports direct-login rejection, expiration checks, and replay prevention.
7. `idp_sessions` stores only a hash of the opaque IdP session cookie value.
8. `login_result_codes` stores one-time callback codes and access token hashes for backend-only token exchange.
9. Roles and permissions may be global when `service_provider_id` is null, or service-specific when scoped to one service provider.
10. User-role and role-permission join tables enforce that assignments cannot point to deleted users, roles, or permissions.

## Edge Cases

- User identifiers must be normalized before insert. The database enforces uniqueness of normalized identifiers but does not decide locale-specific normalization rules.
- A user can be disabled indefinitely with `disabled_at` or temporarily blocked with `locked_until`.
- Session and login result secrets are represented by hashes only. The raw cookie value, callback code, and access token must remain write-only from the database perspective.
- `service_provider_return_urls_https` is a draft guardrail. The application must still parse URLs and reject fragments, userinfo, wildcard matches, and unsafe local-development exceptions.
- PostgreSQL unique constraints do not treat nulls as equal, so global role and permission names use partial unique indexes.
- Role and permission scope consistency is not fully enforceable with the simple join table. A future migration can add triggers or separate global/service-scoped assignment tables if cross-service role-permission links must be rejected at the database layer.
- Challenge and session cleanup should be handled by scheduled deletion or partitioning once retention needs are known.

## Migration Test Targets

When this draft becomes executable migrations, tests should cover:

- duplicate primary email rejection;
- duplicate normalized login identifier rejection;
- one password credential per user;
- duplicate service provider ID rejection;
- duplicate return URL rejection within one service provider;
- challenge, session, and login result foreign-key enforcement;
- login result code and access token hash uniqueness;
- global and service-scoped role name uniqueness;
- global and service-scoped permission name uniqueness;
- user-role and role-permission dangling-reference rejection.
