package login

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrDuplicateServiceProvider           = errors.New("duplicate service provider")
	ErrInvalidServiceProviderRegistration = errors.New("invalid service provider registration")
	ErrDuplicateReturnURL                 = errors.New("duplicate return url")
	ErrWeakServiceSecret                  = errors.New("weak service secret")
	ErrInvalidAdminCredentials            = errors.New("invalid admin credentials")
)

var serviceProviderIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type SaltGenerator func() ([]byte, error)

type ServiceProviderRegistration struct {
	ID                string
	DisplayName       string
	AllowedReturnURLs []string
	Active            bool
	ServiceSecret     string
}

type ServiceProviderRegistrationOptions struct {
	Clock            func() time.Time
	SaltGenerator    SaltGenerator
	SecretIterations int
	SecretKeyLength  int
	MinSecretLength  int
}

type ServiceProviderRegistrationService struct {
	providers        ServiceProviderRegistry
	clock            func() time.Time
	newSalt          SaltGenerator
	secretIterations int
	secretKeyLength  int
	minSecretLength  int
}

func NewServiceProviderRegistrationService(providers ServiceProviderRegistry, options ServiceProviderRegistrationOptions) *ServiceProviderRegistrationService {
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	newSalt := options.SaltGenerator
	if newSalt == nil {
		newSalt = secureSalt
	}
	secretIterations := options.SecretIterations
	if secretIterations == 0 {
		secretIterations = 100000
	}
	secretKeyLength := options.SecretKeyLength
	if secretKeyLength == 0 {
		secretKeyLength = 32
	}
	minSecretLength := options.MinSecretLength
	if minSecretLength == 0 {
		minSecretLength = 16
	}

	return &ServiceProviderRegistrationService{
		providers:        providers,
		clock:            clock,
		newSalt:          newSalt,
		secretIterations: secretIterations,
		secretKeyLength:  secretKeyLength,
		minSecretLength:  minSecretLength,
	}
}

func (s *ServiceProviderRegistrationService) RegisterServiceProvider(ctx context.Context, registration ServiceProviderRegistration) (ServiceProvider, error) {
	id, err := normalizeServiceProviderID(registration.ID)
	if err != nil {
		return ServiceProvider{}, err
	}
	displayName := strings.TrimSpace(registration.DisplayName)
	if displayName == "" {
		return ServiceProvider{}, ErrInvalidServiceProviderRegistration
	}
	returnURLs, err := validateAllowedReturnURLs(registration.AllowedReturnURLs)
	if err != nil {
		return ServiceProvider{}, err
	}
	if len(registration.ServiceSecret) < s.minSecretLength {
		return ServiceProvider{}, ErrWeakServiceSecret
	}

	salt, err := s.newSalt()
	if err != nil {
		return ServiceProvider{}, err
	}
	secretHash, err := NewPBKDF2PasswordHash(registration.ServiceSecret, salt, s.secretIterations, s.secretKeyLength)
	if err != nil {
		return ServiceProvider{}, err
	}

	now := s.clock()
	provider := ServiceProvider{
		ID:                id,
		DisplayName:       displayName,
		AllowedReturnURLs: returnURLs,
		Active:            registration.Active,
		SecretHash:        secretHash,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.providers.RegisterServiceProvider(ctx, provider); err != nil {
		return ServiceProvider{}, err
	}

	return provider, nil
}

func normalizeServiceProviderID(id string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(id))
	if !serviceProviderIDPattern.MatchString(normalized) {
		return "", ErrInvalidServiceProviderRegistration
	}
	return normalized, nil
}

func validateAllowedReturnURLs(returnURLs []string) ([]string, error) {
	if len(returnURLs) == 0 {
		return nil, ErrInvalidServiceProviderRegistration
	}

	seen := make(map[string]struct{}, len(returnURLs))
	valid := make([]string, 0, len(returnURLs))
	for _, raw := range returnURLs {
		trimmed := strings.TrimSpace(raw)
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" {
			return nil, ErrInvalidReturnURL
		}
		if _, exists := seen[trimmed]; exists {
			return nil, ErrDuplicateReturnURL
		}
		seen[trimmed] = struct{}{}
		valid = append(valid, trimmed)
	}

	if len(valid) == 0 {
		return nil, ErrInvalidServiceProviderRegistration
	}
	return valid, nil
}

func secureSalt() ([]byte, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

type AdminAuthenticator interface {
	AuthenticateAdmin(ctx context.Context, r *http.Request) error
}

type StaticAdminAuthenticator string

func (a StaticAdminAuthenticator) AuthenticateAdmin(_ context.Context, r *http.Request) error {
	expected := string(a)
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ErrInvalidAdminCredentials
	}
	actual := strings.TrimPrefix(header, "Bearer ")
	if expected == "" || actual == "" {
		return ErrInvalidAdminCredentials
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return ErrInvalidAdminCredentials
	}
	return nil
}

type ServiceProviderRegistrationHandler struct {
	registrar       *ServiceProviderRegistrationService
	admin           AdminAuthenticator
	maxRequestBytes int64
}

type ServiceProviderRegistrationHandlerOptions struct {
	MaxRequestBytes int64
}

type ServiceProviderRegistrationRequest struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"displayName"`
	AllowedReturnURLs []string `json:"allowedReturnUrls"`
	Active            bool     `json:"active"`
	ServiceSecret     string   `json:"serviceSecret"`
}

type ServiceProviderRegistrationResponse struct {
	ID                string    `json:"id"`
	DisplayName       string    `json:"displayName"`
	AllowedReturnURLs []string  `json:"allowedReturnUrls"`
	Active            bool      `json:"active"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func NewServiceProviderRegistrationHandler(registrar *ServiceProviderRegistrationService, admin AdminAuthenticator, options ServiceProviderRegistrationHandlerOptions) *ServiceProviderRegistrationHandler {
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes == 0 {
		maxRequestBytes = 1 << 20
	}

	return &ServiceProviderRegistrationHandler{
		registrar:       registrar,
		admin:           admin,
		maxRequestBytes: maxRequestBytes,
	}
}

func (h *ServiceProviderRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.registrar == nil || h.admin == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := h.admin.AuthenticateAdmin(r.Context(), r); err != nil {
		if errors.Is(err, ErrInvalidAdminCredentials) {
			writeAdminRegistrationError(w, http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var payload ServiceProviderRegistrationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeAdminRegistrationError(w, http.StatusBadRequest)
		return
	}

	provider, err := h.registrar.RegisterServiceProvider(r.Context(), ServiceProviderRegistration{
		ID:                payload.ID,
		DisplayName:       payload.DisplayName,
		AllowedReturnURLs: payload.AllowedReturnURLs,
		Active:            payload.Active,
		ServiceSecret:     payload.ServiceSecret,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrDuplicateServiceProvider):
			writeAdminRegistrationError(w, http.StatusConflict)
		case errors.Is(err, ErrInvalidServiceProviderRegistration), errors.Is(err, ErrInvalidReturnURL), errors.Is(err, ErrDuplicateReturnURL), errors.Is(err, ErrWeakServiceSecret):
			writeAdminRegistrationError(w, http.StatusBadRequest)
		default:
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ServiceProviderRegistrationResponse{
		ID:                provider.ID,
		DisplayName:       provider.DisplayName,
		AllowedReturnURLs: append([]string(nil), provider.AllowedReturnURLs...),
		Active:            provider.Active,
		CreatedAt:         provider.CreatedAt,
		UpdatedAt:         provider.UpdatedAt,
	})
}

func writeAdminRegistrationError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "invalid service provider registration request",
	})
}
