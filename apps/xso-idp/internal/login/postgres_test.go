package login

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgreSQLStoreRegistersAndFindsServiceProvider(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	store := NewPostgreSQLStore(db)
	provider := ServiceProvider{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		SecretHash: PasswordHash{
			Algorithm:  pbkdf2SHA256Algorithm,
			Salt:       []byte("salt"),
			Iterations: 1000,
			Key:        []byte("key"),
		},
		CreatedAt: time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC),
	}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO service_providers").
		WithArgs(provider.ID, provider.DisplayName, provider.Active, provider.SecretHash.Algorithm, provider.SecretHash.Salt, provider.SecretHash.Iterations, provider.SecretHash.Key, provider.CreatedAt, provider.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO service_provider_return_urls").
		WithArgs(provider.ID, provider.AllowedReturnURLs[0]).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.RegisterServiceProvider(context.Background(), provider); err != nil {
		t.Fatalf("RegisterServiceProvider returned error: %v", err)
	}

	mock.ExpectQuery("SELECT id, display_name, active, secret_algorithm, secret_salt, secret_iterations, secret_key, created_at, updated_at FROM service_providers").
		WithArgs("sample-client").
		WillReturnRows(sqlmock.NewRows([]string{"id", "display_name", "active", "secret_algorithm", "secret_salt", "secret_iterations", "secret_key", "created_at", "updated_at"}).
			AddRow(provider.ID, provider.DisplayName, provider.Active, provider.SecretHash.Algorithm, provider.SecretHash.Salt, provider.SecretHash.Iterations, provider.SecretHash.Key, provider.CreatedAt, provider.UpdatedAt))
	mock.ExpectQuery("SELECT return_url FROM service_provider_return_urls").
		WithArgs("sample-client").
		WillReturnRows(sqlmock.NewRows([]string{"return_url"}).AddRow(provider.AllowedReturnURLs[0]))

	got, ok, err := store.FindServiceProvider(context.Background(), "sample-client")
	if err != nil {
		t.Fatalf("FindServiceProvider returned error: %v", err)
	}
	if !ok {
		t.Fatal("FindServiceProvider ok = false, want true")
	}
	if got.ID != provider.ID || got.DisplayName != provider.DisplayName || got.AllowedReturnURLs[0] != provider.AllowedReturnURLs[0] {
		t.Fatalf("provider = %#v", got)
	}
	if got.SecretHash.Algorithm != pbkdf2SHA256Algorithm || string(got.SecretHash.Salt) != "salt" || string(got.SecretHash.Key) != "key" {
		t.Fatalf("secret hash = %#v", got.SecretHash)
	}
}

func TestPostgreSQLCredentialAuthenticatorAuthenticatesFromCredentialRows(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	hash, err := NewPBKDF2PasswordHash("correct-password", []byte("fixed-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewPostgreSQLCredentialAuthenticator(db)

	mock.ExpectQuery("SELECT u.id, u.display_name, u.disabled_at, u.locked_until, c.password_algorithm, c.password_salt, c.password_iterations, c.password_key").
		WithArgs("ada@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "display_name", "disabled_at", "locked_until", "password_algorithm", "password_salt", "password_iterations", "password_key"}).
			AddRow("user-1", "Ada Lovelace", nil, nil, hash.Algorithm, hash.Salt, hash.Iterations, hash.Key))

	user, err := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: " ADA@example.COM ",
		Password:   "correct-password",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if user.ID != "user-1" || user.DisplayName != "Ada Lovelace" {
		t.Fatalf("user = %#v", user)
	}
}

func TestPostgreSQLCredentialAuthenticatorRejectsMissingUserGenerically(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	authenticator := NewPostgreSQLCredentialAuthenticator(db)
	mock.ExpectQuery("SELECT u.id, u.display_name, u.disabled_at, u.locked_until, c.password_algorithm, c.password_salt, c.password_iterations, c.password_key").
		WithArgs("missing@example.com").
		WillReturnError(sql.ErrNoRows)

	_, err := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: "missing@example.com",
		Password:   "correct-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate error = %v, want ErrInvalidCredentials", err)
	}
}

func TestPostgreSQLChallengeStoreMarksChallengeUsedOnce(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	store := NewPostgreSQLStore(db)
	challenge := Challenge{
		ID:                "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback",
		CSRFToken:         "csrf-1",
		CreatedAt:         time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC),
		ExpiresAt:         time.Date(2026, 5, 11, 10, 5, 0, 0, time.UTC),
	}

	mock.ExpectExec("INSERT INTO login_challenges").
		WithArgs(challenge.ID, challenge.ServiceProviderID, challenge.ReturnURL, challenge.CSRFToken, challenge.ExpiresAt, challenge.CreatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.SaveChallenge(context.Background(), challenge); err != nil {
		t.Fatalf("SaveChallenge returned error: %v", err)
	}

	mock.ExpectExec("UPDATE login_challenges SET used_at = now\\(\\) WHERE id = \\$1 AND used_at IS NULL").
		WithArgs("challenge-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.MarkChallengeUsed(context.Background(), "challenge-1"); err != nil {
		t.Fatalf("first MarkChallengeUsed returned error: %v", err)
	}

	mock.ExpectExec("UPDATE login_challenges SET used_at = now\\(\\) WHERE id = \\$1 AND used_at IS NULL").
		WithArgs("challenge-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT used_at FROM login_challenges").
		WithArgs("challenge-1").
		WillReturnRows(sqlmock.NewRows([]string{"used_at"}).AddRow(time.Date(2026, 5, 11, 10, 1, 0, 0, time.UTC)))

	err := store.MarkChallengeUsed(context.Background(), "challenge-1")
	if !errors.Is(err, ErrUsedChallenge) {
		t.Fatalf("second MarkChallengeUsed error = %v, want ErrUsedChallenge", err)
	}
}

func newSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
	})

	return db, mock
}
