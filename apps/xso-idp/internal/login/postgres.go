package login

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type PostgreSQLStore struct {
	db *sql.DB
}

func NewPostgreSQLStore(db *sql.DB) *PostgreSQLStore {
	return &PostgreSQLStore{db: db}
}

func (s *PostgreSQLStore) RegisterServiceProvider(ctx context.Context, provider ServiceProvider) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	_, err = tx.ExecContext(ctx, `
INSERT INTO service_providers (
    id, display_name, active, secret_algorithm, secret_salt, secret_iterations, secret_key, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		provider.ID,
		provider.DisplayName,
		provider.Active,
		provider.SecretHash.Algorithm,
		provider.SecretHash.Salt,
		provider.SecretHash.Iterations,
		provider.SecretHash.Key,
		provider.CreatedAt,
		provider.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateServiceProvider
		}
		return err
	}

	for _, returnURL := range provider.AllowedReturnURLs {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO service_provider_return_urls (service_provider_id, return_url)
VALUES ($1, $2)`, provider.ID, returnURL); err != nil {
			if isUniqueViolation(err) {
				return ErrDuplicateReturnURL
			}
			return err
		}
	}

	return tx.Commit()
}

func (s *PostgreSQLStore) FindServiceProvider(ctx context.Context, id string) (ServiceProvider, bool, error) {
	var provider ServiceProvider
	err := s.db.QueryRowContext(ctx, `
SELECT id, display_name, active, secret_algorithm, secret_salt, secret_iterations, secret_key, created_at, updated_at
FROM service_providers
WHERE id = $1`,
		id,
	).Scan(
		&provider.ID,
		&provider.DisplayName,
		&provider.Active,
		&provider.SecretHash.Algorithm,
		&provider.SecretHash.Salt,
		&provider.SecretHash.Iterations,
		&provider.SecretHash.Key,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceProvider{}, false, nil
	}
	if err != nil {
		return ServiceProvider{}, false, err
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT return_url
FROM service_provider_return_urls
WHERE service_provider_id = $1
ORDER BY return_url`,
		id,
	)
	if err != nil {
		return ServiceProvider{}, false, err
	}
	defer rows.Close()

	for rows.Next() {
		var returnURL string
		if err := rows.Scan(&returnURL); err != nil {
			return ServiceProvider{}, false, err
		}
		provider.AllowedReturnURLs = append(provider.AllowedReturnURLs, returnURL)
	}
	if err := rows.Err(); err != nil {
		return ServiceProvider{}, false, err
	}

	return provider, true, nil
}

func (s *PostgreSQLStore) SaveChallenge(ctx context.Context, challenge Challenge) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO login_challenges (
    id, service_provider_id, return_url, csrf_token_hash, expires_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6)`,
		challenge.ID,
		challenge.ServiceProviderID,
		challenge.ReturnURL,
		challenge.CSRFToken,
		challenge.ExpiresAt,
		challenge.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateChallenge
		}
		return err
	}
	return nil
}

func (s *PostgreSQLStore) FindChallenge(ctx context.Context, id string) (Challenge, bool, error) {
	var challenge Challenge
	var csrfToken sql.NullString
	var usedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT id, service_provider_id, return_url, csrf_token_hash, expires_at, created_at, used_at
FROM login_challenges
WHERE id = $1`,
		id,
	).Scan(
		&challenge.ID,
		&challenge.ServiceProviderID,
		&challenge.ReturnURL,
		&csrfToken,
		&challenge.ExpiresAt,
		&challenge.CreatedAt,
		&usedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, err
	}
	challenge.CSRFToken = csrfToken.String
	challenge.Used = usedAt.Valid

	return challenge, true, nil
}

func (s *PostgreSQLStore) MarkChallengeUsed(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE login_challenges SET used_at = now() WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	var usedAt sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT used_at FROM login_challenges WHERE id = $1`, id).Scan(&usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownChallenge
	}
	if err != nil {
		return err
	}
	if usedAt.Valid {
		return ErrUsedChallenge
	}

	return ErrUnknownChallenge
}

func (s *PostgreSQLStore) SaveIDPSession(ctx context.Context, session IDPSession) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO idp_sessions (
    session_hash, user_id, created_at, last_seen_at, expires_at, idle_expires_at
) VALUES ($1, $2, $3, $4, $5, $6)`,
		session.ID,
		session.UserID,
		session.CreatedAt,
		session.LastSeenAt,
		session.ExpiresAt,
		session.IdleExpiresAt,
	)
	return err
}

func (s *PostgreSQLStore) FindIDPSession(ctx context.Context, id string) (IDPSession, bool, error) {
	var session IDPSession
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT session_hash, user_id, created_at, last_seen_at, expires_at, idle_expires_at, revoked_at
FROM idp_sessions
WHERE session_hash = $1`,
		id,
	).Scan(&session.ID, &session.UserID, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.IdleExpiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IDPSession{}, false, nil
	}
	if err != nil {
		return IDPSession{}, false, err
	}
	return session, !revokedAt.Valid, nil
}

func (s *PostgreSQLStore) SaveLoginResult(ctx context.Context, result LoginResult) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO login_result_codes (
    code_hash, service_provider_id, user_id, session_hash, access_token_hash, issued_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		result.Code,
		result.ServiceProviderID,
		result.UserID,
		result.SessionID,
		result.AccessToken,
		result.IssuedAt,
		result.ExpiresAt,
	)
	return err
}

func (s *PostgreSQLStore) FindLoginResult(ctx context.Context, code string) (LoginResult, bool, error) {
	var result LoginResult
	var usedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT code_hash, service_provider_id, user_id, session_hash, access_token_hash, issued_at, expires_at, used_at
FROM login_result_codes
WHERE code_hash = $1`,
		code,
	).Scan(&result.Code, &result.ServiceProviderID, &result.UserID, &result.SessionID, &result.AccessToken, &result.IssuedAt, &result.ExpiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginResult{}, false, nil
	}
	if err != nil {
		return LoginResult{}, false, err
	}
	result.Used = usedAt.Valid
	return result, true, nil
}

func (s *PostgreSQLStore) MarkLoginResultUsed(ctx context.Context, code string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE login_result_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL`, code)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	var usedAt sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT used_at FROM login_result_codes WHERE code_hash = $1`, code).Scan(&usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownLoginResultCode
	}
	if err != nil {
		return err
	}
	if usedAt.Valid {
		return ErrLoginResultCodeUsed
	}

	return ErrUnknownLoginResultCode
}

type PostgreSQLCredentialAuthenticator struct {
	db *sql.DB
}

func NewPostgreSQLCredentialAuthenticator(db *sql.DB) *PostgreSQLCredentialAuthenticator {
	return &PostgreSQLCredentialAuthenticator{db: db}
}

func (a *PostgreSQLCredentialAuthenticator) Authenticate(ctx context.Context, credentials LoginCredentials) (LoginUser, error) {
	identifier := normalizeIdentifier(credentials.Identifier)
	if identifier == "" || credentials.Password == "" {
		return LoginUser{}, ErrInvalidCredentials
	}

	var user LoginUser
	var disabledAt sql.NullTime
	var lockedUntil sql.NullTime
	var hash PasswordHash
	err := a.db.QueryRowContext(ctx, `
SELECT u.id, u.display_name, u.disabled_at, u.locked_until, c.password_algorithm, c.password_salt, c.password_iterations, c.password_key
FROM user_identifiers i
JOIN users u ON u.id = i.user_id
JOIN user_credentials c ON c.user_id = u.id AND c.credential_type = 'password'
WHERE i.normalized_identifier = $1`,
		identifier,
	).Scan(&user.ID, &user.DisplayName, &disabledAt, &lockedUntil, &hash.Algorithm, &hash.Salt, &hash.Iterations, &hash.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginUser{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginUser{}, err
	}
	if err := verifyPasswordHash(credentials.Password, hash); err != nil {
		if errors.Is(err, ErrUnsupportedPasswordHash) {
			return LoginUser{}, err
		}
		return LoginUser{}, ErrInvalidCredentials
	}
	if disabledAt.Valid {
		return LoginUser{}, ErrUserDisabled
	}
	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return LoginUser{}, ErrUserLocked
	}

	return user, nil
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "sqlstate 23505")
}
