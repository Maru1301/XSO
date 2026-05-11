package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMemoryCredentialAuthenticatorAuthenticatesNormalizedIdentifier(t *testing.T) {
	hash, err := NewPBKDF2PasswordHash("correct-password", []byte("fixed-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryCredentialAuthenticator([]UserAccount{{
		ID:           "user-1",
		DisplayName:  "Ada Lovelace",
		Identifiers:  []string{"ada@example.com", "E1001"},
		PasswordHash: hash,
	}})

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

func TestMemoryCredentialAuthenticatorRejectsUnknownUserAndBadPasswordGenerically(t *testing.T) {
	hash, err := NewPBKDF2PasswordHash("correct-password", []byte("fixed-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryCredentialAuthenticator([]UserAccount{{
		ID:           "user-1",
		Identifiers:  []string{"ada@example.com"},
		PasswordHash: hash,
	}})

	_, unknownErr := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: "unknown@example.com",
		Password:   "correct-password",
	})
	_, badPasswordErr := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: "ada@example.com",
		Password:   "bad-password",
	})

	if !errors.Is(unknownErr, ErrInvalidCredentials) {
		t.Fatalf("unknownErr = %v, want ErrInvalidCredentials", unknownErr)
	}
	if !errors.Is(badPasswordErr, ErrInvalidCredentials) {
		t.Fatalf("badPasswordErr = %v, want ErrInvalidCredentials", badPasswordErr)
	}
	if unknownErr.Error() != badPasswordErr.Error() {
		t.Fatalf("error messages differ: %q vs %q", unknownErr.Error(), badPasswordErr.Error())
	}
}

func TestMemoryCredentialAuthenticatorRejectsDisabledAndLockedUsers(t *testing.T) {
	hash, err := NewPBKDF2PasswordHash("correct-password", []byte("fixed-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryCredentialAuthenticator([]UserAccount{
		{
			ID:           "disabled",
			Identifiers:  []string{"disabled@example.com"},
			PasswordHash: hash,
			Disabled:     true,
		},
		{
			ID:           "locked",
			Identifiers:  []string{"locked@example.com"},
			PasswordHash: hash,
			Locked:       true,
		},
	})

	_, disabledErr := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: "disabled@example.com",
		Password:   "correct-password",
	})
	_, lockedErr := authenticator.Authenticate(context.Background(), LoginCredentials{
		Identifier: "locked@example.com",
		Password:   "correct-password",
	})

	if !errors.Is(disabledErr, ErrUserDisabled) {
		t.Fatalf("disabledErr = %v, want ErrUserDisabled", disabledErr)
	}
	if !errors.Is(lockedErr, ErrUserLocked) {
		t.Fatalf("lockedErr = %v, want ErrUserLocked", lockedErr)
	}
}

func TestLoginResultIssuerCreatesIdPSessionAndBrowserSafeCodeRedirect(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	sessionStore := NewMemoryIDPSessionStore()
	issuer := NewLoginResultIssuer(
		sessionStore,
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return now },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)

	session, err := issuer.IssueSession(context.Background(), LoginSessionRequest{
		ChallengeID:       "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback?existing=1",
		User: LoginUser{
			ID:          "user-1",
			DisplayName: "Ada Lovelace",
		},
	})

	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}
	if len(session.Cookies) != 1 {
		t.Fatalf("cookies = %#v, want one IdP session cookie", session.Cookies)
	}
	cookie := session.Cookies[0]
	if cookie.Name != "xso_idp_session" || cookie.Value != "session-1" {
		t.Fatalf("cookie = %#v", cookie)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("cookie security attributes = %#v", cookie)
	}
	if !cookie.Expires.Equal(now.Add(8 * time.Hour)) {
		t.Fatalf("cookie expires = %v, want %v", cookie.Expires, now.Add(8*time.Hour))
	}
	storedSession, ok, err := sessionStore.FindIDPSession(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("FindIDPSession returned error: %v", err)
	}
	if !ok {
		t.Fatal("IdP session was not stored")
	}
	if !storedSession.IdleExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("idle expiry = %v, want %v", storedSession.IdleExpiresAt, now.Add(30*time.Minute))
	}

	redirectURL, err := url.Parse(session.RedirectURL)
	if err != nil {
		t.Fatalf("redirect URL parse failed: %v", err)
	}
	if got := redirectURL.Query().Get("code"); got != "code-1" {
		t.Fatalf("code = %q, want code-1", got)
	}
	if strings.Contains(session.RedirectURL, "access-token-1") {
		t.Fatalf("redirect URL leaks access token: %s", session.RedirectURL)
	}

	result, err := issuer.ExchangeLoginResultCode(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("ExchangeLoginResultCode returned error: %v", err)
	}
	if result.AccessToken != "access-token-1" || result.UserID != "user-1" || result.ServiceProviderID != "sample-client" {
		t.Fatalf("login result = %#v", result)
	}
	if !result.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("access token expires = %v, want %v", result.ExpiresAt, now.Add(5*time.Minute))
	}

	_, err = issuer.ExchangeLoginResultCode(context.Background(), "code-1")
	if !errors.Is(err, ErrLoginResultCodeUsed) {
		t.Fatalf("second exchange error = %v, want ErrLoginResultCodeUsed", err)
	}
}

func TestLoginResultIssuerRejectsExpiredCode(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	currentTime := now
	issuer := NewLoginResultIssuer(
		NewMemoryIDPSessionStore(),
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return currentTime },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)
	_, err := issuer.IssueSession(context.Background(), LoginSessionRequest{
		ChallengeID:       "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback",
		User:              LoginUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}

	currentTime = now.Add(5*time.Minute + time.Second)

	_, err = issuer.ExchangeLoginResultCode(context.Background(), "code-1")
	if !errors.Is(err, ErrLoginResultCodeExpired) {
		t.Fatalf("ExchangeLoginResultCode error = %v, want ErrLoginResultCodeExpired", err)
	}
}

func TestLoginSubmitHandlerDoesNotExposeAccessTokenToBrowser(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	challenges := newTestChallengeService(now)
	challenge, err := challenges.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	hash, err := NewPBKDF2PasswordHash("correct-password", []byte("fixed-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryCredentialAuthenticator([]UserAccount{{
		ID:           "user-1",
		Identifiers:  []string{"ada@example.com"},
		PasswordHash: hash,
	}})
	issuer := NewLoginResultIssuer(
		NewMemoryIDPSessionStore(),
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return now },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)
	handler := NewLoginSubmitHandler(challenges, authenticator, issuer, LoginSubmitHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONLoginRequest(challenge.ID, "ada@example.com", "correct-password"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if strings.Contains(body, "access-token-1") {
		t.Fatalf("response body leaks access token: %s", body)
	}
	if !strings.Contains(body, "code-1") {
		t.Fatalf("response body does not include login result code: %s", body)
	}
}

func TestMemoryServiceProviderAuthenticatorAuthenticatesActiveService(t *testing.T) {
	secretHash, err := NewPBKDF2PasswordHash("service-secret", []byte("service-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryServiceProviderAuthenticator(NewMemoryServiceProviderStore([]ServiceProvider{{
		ID:          "sample-client",
		DisplayName: "Sample Client",
		Active:      true,
		SecretHash:  secretHash,
	}}))

	provider, err := authenticator.AuthenticateServiceProvider(context.Background(), ServiceProviderCredentials{
		ServiceProviderID: "sample-client",
		Secret:            "service-secret",
	})

	if err != nil {
		t.Fatalf("AuthenticateServiceProvider returned error: %v", err)
	}
	if provider.ID != "sample-client" {
		t.Fatalf("provider = %#v", provider)
	}
}

func TestMemoryServiceProviderAuthenticatorRejectsUnknownInactiveAndBadSecretGenerically(t *testing.T) {
	secretHash, err := NewPBKDF2PasswordHash("service-secret", []byte("service-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}
	authenticator := NewMemoryServiceProviderAuthenticator(NewMemoryServiceProviderStore([]ServiceProvider{
		{
			ID:         "sample-client",
			Active:     true,
			SecretHash: secretHash,
		},
		{
			ID:         "inactive-client",
			Active:     false,
			SecretHash: secretHash,
		},
	}))

	cases := []ServiceProviderCredentials{
		{ServiceProviderID: "missing-client", Secret: "service-secret"},
		{ServiceProviderID: "inactive-client", Secret: "service-secret"},
		{ServiceProviderID: "sample-client", Secret: "bad-secret"},
	}
	for _, tc := range cases {
		_, err := authenticator.AuthenticateServiceProvider(context.Background(), tc)
		if !errors.Is(err, ErrInvalidServiceProviderCredentials) {
			t.Fatalf("AuthenticateServiceProvider(%#v) error = %v, want ErrInvalidServiceProviderCredentials", tc, err)
		}
	}
}

func TestLoginResultExchangeHandlerReturnsAccessTokenToServiceBackend(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	issuer := NewLoginResultIssuer(
		NewMemoryIDPSessionStore(),
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return now },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)
	_, err := issuer.IssueSession(context.Background(), LoginSessionRequest{
		ChallengeID:       "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback",
		User:              LoginUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}
	serviceAuth := newTestServiceProviderAuthenticator(t, "sample-client", "service-secret")
	handler := NewLoginResultExchangeHandler(issuer, serviceAuth, LoginResultExchangeHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONExchangeRequest("sample-client", "service-secret", "code-1"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body loginResultExchangeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if body.AccessToken != "access-token-1" || body.TokenType != "Bearer" || body.ExpiresIn != 300 {
		t.Fatalf("exchange response = %#v", body)
	}

	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, newJSONExchangeRequest("sample-client", "service-secret", "code-1"))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusBadRequest)
	}
}

func TestLoginResultExchangeHandlerRejectsBadServiceCredentialsWithoutUsingCode(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	issuer := newTestLoginResultIssuer(t, now, "sample-client")
	serviceAuth := newTestServiceProviderAuthenticator(t, "sample-client", "service-secret")
	handler := NewLoginResultExchangeHandler(issuer, serviceAuth, LoginResultExchangeHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONExchangeRequest("sample-client", "bad-secret", "code-1"))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(response.Body.String(), "access-token-1") {
		t.Fatalf("response leaks access token: %s", response.Body.String())
	}

	result, err := issuer.ExchangeLoginResultCodeForService(context.Background(), "sample-client", "code-1")
	if err != nil {
		t.Fatalf("code should remain usable after bad service credentials, got %v", err)
	}
	if result.AccessToken != "access-token-1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestLoginResultExchangeHandlerRejectsWrongAudienceWithoutUsingCode(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	issuer := newTestLoginResultIssuer(t, now, "sample-client")
	serviceAuth := newTestServiceProviderAuthenticator(t, "other-client", "service-secret")
	handler := NewLoginResultExchangeHandler(issuer, serviceAuth, LoginResultExchangeHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONExchangeRequest("other-client", "service-secret", "code-1"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}

	result, err := issuer.ExchangeLoginResultCodeForService(context.Background(), "sample-client", "code-1")
	if err != nil {
		t.Fatalf("code should remain usable for correct service, got %v", err)
	}
	if result.AccessToken != "access-token-1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestLoginResultExchangeHandlerRejectsExpiredCode(t *testing.T) {
	now := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	currentTime := now
	issuer := NewLoginResultIssuer(
		NewMemoryIDPSessionStore(),
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return currentTime },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)
	_, err := issuer.IssueSession(context.Background(), LoginSessionRequest{
		ChallengeID:       "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback",
		User:              LoginUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}
	currentTime = now.Add(5*time.Minute + time.Second)
	handler := NewLoginResultExchangeHandler(issuer, newTestServiceProviderAuthenticator(t, "sample-client", "service-secret"), LoginResultExchangeHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONExchangeRequest("sample-client", "service-secret", "code-1"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if strings.Contains(response.Body.String(), "access-token-1") {
		t.Fatalf("response leaks access token: %s", response.Body.String())
	}
}

func newTestLoginResultIssuer(t *testing.T, now time.Time, serviceProviderID string) *LoginResultIssuer {
	t.Helper()

	issuer := NewLoginResultIssuer(
		NewMemoryIDPSessionStore(),
		NewMemoryLoginResultStore(),
		LoginResultIssuerOptions{
			Clock:                func() time.Time { return now },
			SessionIDGenerator:   fixedGenerator("session-1"),
			CodeGenerator:        fixedGenerator("code-1"),
			AccessTokenGenerator: fixedGenerator("access-token-1"),
		},
	)
	_, err := issuer.IssueSession(context.Background(), LoginSessionRequest{
		ChallengeID:       "challenge-1",
		ServiceProviderID: serviceProviderID,
		ReturnURL:         "https://sample.example.com/auth/callback",
		User:              LoginUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}

	return issuer
}

func newTestServiceProviderAuthenticator(t *testing.T, serviceProviderID string, secret string) *MemoryServiceProviderAuthenticator {
	t.Helper()

	secretHash, err := NewPBKDF2PasswordHash(secret, []byte(serviceProviderID+"-salt"), 1000, 32)
	if err != nil {
		t.Fatalf("NewPBKDF2PasswordHash returned error: %v", err)
	}

	return NewMemoryServiceProviderAuthenticator(NewMemoryServiceProviderStore([]ServiceProvider{{
		ID:          serviceProviderID,
		DisplayName: serviceProviderID,
		Active:      true,
		SecretHash:  secretHash,
	}}))
}

func newJSONExchangeRequest(serviceProviderID string, serviceSecret string, code string) *http.Request {
	body, err := json.Marshal(loginResultExchangeRequest{
		ServiceProviderID: serviceProviderID,
		ServiceSecret:     serviceSecret,
		Code:              code,
	})
	if err != nil {
		panic(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/login/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
