package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoginPageHandlerServesAppForValidChallenge(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	handler := NewLoginPageHandler(service, LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
	body := response.Body.String()
	if !strings.Contains(body, `<div id="app"`) {
		t.Fatalf("response body does not contain Vue app mount point: %s", body)
	}
	if !strings.Contains(body, `data-challenge-id="`+challenge.ID+`"`) {
		t.Fatalf("response body does not include escaped challenge context: %s", body)
	}
}

func TestLoginPageHandlerRejectsDirectAccessWithoutChallenge(t *testing.T) {
	handler := NewLoginPageHandler(newTestChallengeService(time.Now()), LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginPageHandlerRejectsUnknownChallenge(t *testing.T) {
	handler := NewLoginPageHandler(newTestChallengeService(time.Now()), LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge=missing", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginPageHandlerRejectsExpiredChallenge(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	service.clock = func() time.Time {
		return now.Add(5*time.Minute + time.Second)
	}
	handler := NewLoginPageHandler(service, LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginPageHandlerRejectsUsedChallenge(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	if err := service.MarkChallengeUsed(context.Background(), challenge.ID); err != nil {
		t.Fatalf("MarkChallengeUsed returned error: %v", err)
	}
	handler := NewLoginPageHandler(service, LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginPageHandlerRejectsInactiveServiceProvider(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	providers := service.providers.(*MemoryServiceProviderStore)
	provider := providers.providers["sample-client"]
	provider.Active = false
	providers.providers["sample-client"] = provider
	handler := NewLoginPageHandler(service, LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginPageHandlerReturnsServerErrorForUnexpectedValidatorError(t *testing.T) {
	handler := NewLoginPageHandler(failingChallengeValidator{}, LoginPageHandlerOptions{
		DistDir: newTestLoginDist(t),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge=challenge-1", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestLoginPageHandlerReturnsServerErrorWhenBuiltIndexIsMissing(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	handler := NewLoginPageHandler(service, LoginPageHandlerOptions{
		DistDir: t.TempDir(),
	})

	request := httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestLoginAssetHandlerServesBuiltAssets(t *testing.T) {
	distDir := newTestLoginDist(t)
	handler := NewLoginAssetHandler(distDir)

	request := httptest.NewRequest(http.MethodGet, "/login-assets/assets/app.js", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if body := response.Body.String(); body != "console.log('xso')\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestLoginAssetHandlerDoesNotServeBuiltIndex(t *testing.T) {
	distDir := newTestLoginDist(t)
	handler := NewLoginAssetHandler(distDir)

	request := httptest.NewRequest(http.MethodGet, "/login-assets/index.html", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginSubmitHandlerCompletesLoginForValidCredentials(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	authenticator := &stubAuthenticator{
		user: LoginUser{
			ID:          "user-1",
			DisplayName: "Ada Lovelace",
		},
	}
	sessionIssuer := &stubSessionIssuer{
		session: LoginSession{
			Cookies: []http.Cookie{{
				Name:     "xso_session",
				Value:    "session-1",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			}},
		},
	}
	handler := NewLoginSubmitHandler(service, authenticator, sessionIssuer, LoginSubmitHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONLoginRequest(challenge.ID, "ada", "correct-password"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if authenticator.credentials.Identifier != "ada" || authenticator.credentials.Password != "correct-password" {
		t.Fatalf("credentials = %#v", authenticator.credentials)
	}
	if sessionIssuer.request.ChallengeID != challenge.ID || sessionIssuer.request.User.ID != "user-1" {
		t.Fatalf("session request = %#v", sessionIssuer.request)
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != "xso_session" {
		t.Fatalf("cookies = %#v, want xso_session", cookies)
	}

	var body loginSubmitResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if body.RedirectURL != "https://sample.example.com/auth/callback" {
		t.Fatalf("redirectUrl = %q", body.RedirectURL)
	}

	if _, err := service.ValidateChallenge(context.Background(), challenge.ID); !errors.Is(err, ErrUsedChallenge) {
		t.Fatalf("ValidateChallenge error = %v, want ErrUsedChallenge", err)
	}
}

func TestLoginSubmitHandlerRejectsMissingCredentials(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	authenticator := &recordingAuthenticator{}
	handler := NewLoginSubmitHandler(service, authenticator, &stubSessionIssuer{}, LoginSubmitHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONLoginRequest(challenge.ID, "ada", ""))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if authenticator.called {
		t.Fatal("authenticator was called for missing credentials")
	}
}

func TestLoginSubmitHandlerRejectsInvalidCredentialsWithGenericError(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	handler := NewLoginSubmitHandler(service, &stubAuthenticator{err: ErrInvalidCredentials}, &stubSessionIssuer{}, LoginSubmitHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONLoginRequest(challenge.ID, "unknown-user", "bad-password"))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	body := response.Body.String()
	if strings.Contains(body, "unknown-user") || strings.Contains(body, "ErrInvalidCredentials") {
		t.Fatalf("response leaks credential detail: %s", body)
	}
	if _, err := service.ValidateChallenge(context.Background(), challenge.ID); err != nil {
		t.Fatalf("challenge should remain reusable after invalid credentials, got %v", err)
	}
}

func TestLoginSubmitHandlerRejectsExpiredChallenge(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	service.clock = func() time.Time {
		return now.Add(5*time.Minute + time.Second)
	}
	handler := NewLoginSubmitHandler(service, &stubAuthenticator{}, &stubSessionIssuer{}, LoginSubmitHandlerOptions{})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONLoginRequest(challenge.ID, "ada", "correct-password"))

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLoginSubmitHandlerRejectsDuplicateSubmission(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	handler := NewLoginSubmitHandler(service, &stubAuthenticator{}, &stubSessionIssuer{}, LoginSubmitHandlerOptions{})

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newJSONLoginRequest(challenge.ID, "ada", "correct-password"))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, newJSONLoginRequest(challenge.ID, "ada", "correct-password"))
	if second.Code != http.StatusNotFound {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusNotFound)
	}
}

func TestLoginSubmitHandlerRejectsMalformedJSON(t *testing.T) {
	handler := NewLoginSubmitHandler(newTestChallengeService(time.Now()), &stubAuthenticator{}, &stubSessionIssuer{}, LoginSubmitHandlerOptions{})

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestLoginHandlerRoutesGetAndPost(t *testing.T) {
	service := newTestChallengeService(time.Now())
	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	handler := NewLoginHandler(
		NewLoginPageHandler(service, LoginPageHandlerOptions{DistDir: newTestLoginDist(t)}),
		NewLoginSubmitHandler(service, &stubAuthenticator{}, &stubSessionIssuer{}, LoginSubmitHandlerOptions{}),
	)

	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/login?challenge="+challenge.ID, nil))
	if getResponse.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", getResponse.Code, http.StatusOK)
	}

	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, newJSONLoginRequest(challenge.ID, "ada", "correct-password"))
	if postResponse.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", postResponse.Code, http.StatusOK)
	}
}

type failingChallengeValidator struct{}

func (failingChallengeValidator) ValidateChallenge(context.Context, string) (Challenge, error) {
	return Challenge{}, errors.New("database unavailable")
}

type stubAuthenticator struct {
	credentials LoginCredentials
	user        LoginUser
	err         error
}

func (a *stubAuthenticator) Authenticate(_ context.Context, credentials LoginCredentials) (LoginUser, error) {
	a.credentials = credentials
	if a.err != nil {
		return LoginUser{}, a.err
	}
	if a.user.ID == "" {
		return LoginUser{ID: "user-1"}, nil
	}
	return a.user, nil
}

type recordingAuthenticator struct {
	called bool
}

func (a *recordingAuthenticator) Authenticate(_ context.Context, _ LoginCredentials) (LoginUser, error) {
	a.called = true
	return LoginUser{}, nil
}

type stubSessionIssuer struct {
	request LoginSessionRequest
	session LoginSession
	err     error
}

func (i *stubSessionIssuer) IssueSession(_ context.Context, request LoginSessionRequest) (LoginSession, error) {
	i.request = request
	if i.err != nil {
		return LoginSession{}, i.err
	}
	return i.session, nil
}

func newJSONLoginRequest(challengeID string, identifier string, password string) *http.Request {
	body, err := json.Marshal(loginSubmitRequest{
		ChallengeID: challengeID,
		Identifier:  identifier,
		Password:    password,
	})
	if err != nil {
		panic(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func newTestLoginDist(t *testing.T) string {
	t.Helper()

	distDir := t.TempDir()
	assetsDir := filepath.Join(distDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	index := `<!doctype html>
<html lang="en">
  <head>
    <script type="module" crossorigin src="/login-assets/assets/app.js"></script>
  </head>
  <body>
    <div id="app"></div>
  </body>
</html>`
	if err := os.WriteFile(filepath.Join(distDir, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatalf("WriteFile index returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte("console.log('xso')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile asset returned error: %v", err)
	}

	return distDir
}
