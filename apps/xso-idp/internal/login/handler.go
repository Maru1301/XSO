package login

import (
	"context"
	"encoding/json"
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

type ChallengeManager interface {
	ChallengeValidator
	MarkChallengeUsed(ctx context.Context, id string) error
}

type LoginCredentials struct {
	Identifier string
	Password   string
}

type LoginUser struct {
	ID          string
	DisplayName string
}

type LoginAuthenticator interface {
	Authenticate(ctx context.Context, credentials LoginCredentials) (LoginUser, error)
}

type LoginSessionRequest struct {
	ChallengeID       string
	ServiceProviderID string
	User              LoginUser
}

type LoginSession struct {
	Cookies []http.Cookie
}

type LoginSessionIssuer interface {
	IssueSession(ctx context.Context, request LoginSessionRequest) (LoginSession, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserDisabled       = errors.New("user disabled")
)

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

type LoginHandler struct {
	page   http.Handler
	submit http.Handler
}

func NewLoginHandler(page http.Handler, submit http.Handler) *LoginHandler {
	return &LoginHandler{
		page:   page,
		submit: submit,
	}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.page.ServeHTTP(w, r)
	case http.MethodPost:
		h.submit.ServeHTTP(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

type LoginSubmitHandler struct {
	challenges      ChallengeManager
	authenticator   LoginAuthenticator
	sessionIssuer   LoginSessionIssuer
	maxRequestBytes int64
}

type LoginSubmitHandlerOptions struct {
	MaxRequestBytes int64
}

type loginSubmitRequest struct {
	ChallengeID string `json:"challengeId"`
	Identifier  string `json:"identifier"`
	Password    string `json:"password"`
}

type loginSubmitResponse struct {
	RedirectURL string `json:"redirectUrl"`
}

func NewLoginSubmitHandler(challenges ChallengeManager, authenticator LoginAuthenticator, sessionIssuer LoginSessionIssuer, options LoginSubmitHandlerOptions) *LoginSubmitHandler {
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes == 0 {
		maxRequestBytes = 1 << 20
	}

	return &LoginSubmitHandler{
		challenges:      challenges,
		authenticator:   authenticator,
		sessionIssuer:   sessionIssuer,
		maxRequestBytes: maxRequestBytes,
	}
}

func (h *LoginSubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.authenticator == nil || h.sessionIssuer == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	var payload loginSubmitRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeLoginError(w, http.StatusBadRequest)
		return
	}

	challenge, err := h.challenges.ValidateChallenge(r.Context(), payload.ChallengeID)
	if err != nil {
		if isChallengeAccessError(err) {
			http.NotFound(w, r)
			return
		}

		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	credentials := LoginCredentials{
		Identifier: strings.TrimSpace(payload.Identifier),
		Password:   payload.Password,
	}
	if credentials.Identifier == "" || credentials.Password == "" {
		writeLoginError(w, http.StatusBadRequest)
		return
	}

	user, err := h.authenticator.Authenticate(r.Context(), credentials)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) {
			writeLoginError(w, http.StatusUnauthorized)
			return
		}

		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	session, err := h.sessionIssuer.IssueSession(r.Context(), LoginSessionRequest{
		ChallengeID:       challenge.ID,
		ServiceProviderID: challenge.ServiceProviderID,
		User:              user,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := h.challenges.MarkChallengeUsed(r.Context(), challenge.ID); err != nil {
		if isChallengeAccessError(err) {
			http.NotFound(w, r)
			return
		}

		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	for _, cookie := range session.Cookies {
		http.SetCookie(w, &cookie)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(loginSubmitResponse{RedirectURL: challenge.ReturnURL})
}

func writeLoginError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "invalid login request",
	})
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
