package login

import (
	"context"
	"errors"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ChallengeValidator interface {
	ValidateChallenge(ctx context.Context, id string) (Challenge, error)
}

type LoginPageHandler struct {
	validator ChallengeValidator
	distDir   string
}

type LoginPageHandlerOptions struct {
	DistDir string
}

func NewLoginPageHandler(validator ChallengeValidator, options LoginPageHandlerOptions) *LoginPageHandler {
	return &LoginPageHandler{
		validator: validator,
		distDir:   options.DistDir,
	}
}

func (h *LoginPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := h.validator.ValidateChallenge(r.Context(), r.URL.Query().Get("challenge"))
	if err != nil {
		if isChallengeAccessError(err) {
			http.NotFound(w, r)
			return
		}

		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	page, err := h.loginPageHTML(challenge)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

func isChallengeAccessError(err error) bool {
	return errors.Is(err, ErrMissingChallenge) ||
		errors.Is(err, ErrUnknownChallenge) ||
		errors.Is(err, ErrExpiredChallenge) ||
		errors.Is(err, ErrUsedChallenge) ||
		errors.Is(err, ErrInactiveServiceProvider) ||
		errors.Is(err, ErrInvalidReturnURL)
}

func (h *LoginPageHandler) loginPageHTML(challenge Challenge) (string, error) {
	page, err := os.ReadFile(filepath.Join(h.distDir, "index.html"))
	if err != nil {
		return "", err
	}

	challengeID := html.EscapeString(challenge.ID)
	return strings.Replace(string(page), `<div id="app"></div>`, `<div id="app" data-challenge-id="`+challengeID+`"></div>`, 1), nil
}

func NewLoginAssetHandler(distDir string) http.Handler {
	fileServer := http.FileServer(http.Dir(distDir))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := filepath.ToSlash(filepath.Clean("/" + strings.TrimPrefix(r.URL.Path, "/login-assets/")))
		if cleanPath == "/index.html" || cleanPath == "/" || cleanPath == "." {
			http.NotFound(w, r)
			return
		}

		request := r.Clone(r.Context())
		request.URL.Path = cleanPath
		fileServer.ServeHTTP(w, request)
	})
}
