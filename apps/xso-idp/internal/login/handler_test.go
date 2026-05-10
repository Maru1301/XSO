package login

import (
	"context"
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

type failingChallengeValidator struct{}

func (failingChallengeValidator) ValidateChallenge(context.Context, string) (Challenge, error) {
	return Challenge{}, errors.New("database unavailable")
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
