package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceProviderRegistrationServiceRegistersProviderForChallengeAndTokenExchange(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	providers := NewMemoryServiceProviderStore(nil)
	registrar := NewServiceProviderRegistrationService(providers, ServiceProviderRegistrationOptions{
		Clock: func() time.Time { return now },
		SaltGenerator: func() ([]byte, error) {
			return []byte("service-salt"), nil
		},
		SecretIterations: 1000,
	})

	registered, err := registrar.RegisterServiceProvider(context.Background(), ServiceProviderRegistration{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	})
	if err != nil {
		t.Fatalf("RegisterServiceProvider returned error: %v", err)
	}
	if registered.ID != "sample-client" || registered.DisplayName != "Sample Client" {
		t.Fatalf("registered provider = %#v", registered)
	}
	if !registered.CreatedAt.Equal(now) || !registered.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps = %v/%v, want %v", registered.CreatedAt, registered.UpdatedAt, now)
	}
	if registered.SecretHash.Algorithm == "" || string(registered.SecretHash.Salt) != "service-salt" {
		t.Fatalf("secret verifier was not persisted: %#v", registered.SecretHash)
	}

	challenges := NewChallengeService(providers, NewMemoryChallengeStore(), ChallengeServiceOptions{
		Clock:         func() time.Time { return now },
		IDGenerator:   fixedGenerator("challenge-1"),
		CSRFGenerator: fixedGenerator("csrf-1"),
	})
	challenge, err := challenges.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	if challenge.ServiceProviderID != "sample-client" {
		t.Fatalf("challenge = %#v", challenge)
	}

	authenticator := NewMemoryServiceProviderAuthenticator(providers)
	provider, err := authenticator.AuthenticateServiceProvider(context.Background(), ServiceProviderCredentials{
		ServiceProviderID: "sample-client",
		Secret:            "strong-service-secret",
	})
	if err != nil {
		t.Fatalf("AuthenticateServiceProvider returned error: %v", err)
	}
	if provider.ID != "sample-client" {
		t.Fatalf("provider = %#v", provider)
	}
}

func TestServiceProviderRegistrationServiceRejectsDuplicateID(t *testing.T) {
	registrar := newTestServiceProviderRegistrar()
	request := ServiceProviderRegistration{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}
	if _, err := registrar.RegisterServiceProvider(context.Background(), request); err != nil {
		t.Fatalf("first RegisterServiceProvider returned error: %v", err)
	}

	_, err := registrar.RegisterServiceProvider(context.Background(), request)
	if !errors.Is(err, ErrDuplicateServiceProvider) {
		t.Fatalf("second RegisterServiceProvider error = %v, want ErrDuplicateServiceProvider", err)
	}
}

func TestServiceProviderRegistrationServiceRejectsMissingFieldsInvalidURLsAndWeakSecret(t *testing.T) {
	cases := []struct {
		name    string
		request ServiceProviderRegistration
		wantErr error
	}{
		{
			name: "missing id",
			request: ServiceProviderRegistration{
				DisplayName:       "Sample Client",
				AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
				ServiceSecret:     "strong-service-secret",
			},
			wantErr: ErrInvalidServiceProviderRegistration,
		},
		{
			name: "missing display name",
			request: ServiceProviderRegistration{
				ID:                "sample-client",
				AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
				ServiceSecret:     "strong-service-secret",
			},
			wantErr: ErrInvalidServiceProviderRegistration,
		},
		{
			name: "empty return urls",
			request: ServiceProviderRegistration{
				ID:            "sample-client",
				DisplayName:   "Sample Client",
				ServiceSecret: "strong-service-secret",
			},
			wantErr: ErrInvalidServiceProviderRegistration,
		},
		{
			name: "relative return url",
			request: ServiceProviderRegistration{
				ID:                "sample-client",
				DisplayName:       "Sample Client",
				AllowedReturnURLs: []string{"/callback"},
				ServiceSecret:     "strong-service-secret",
			},
			wantErr: ErrInvalidReturnURL,
		},
		{
			name: "http return url",
			request: ServiceProviderRegistration{
				ID:                "sample-client",
				DisplayName:       "Sample Client",
				AllowedReturnURLs: []string{"http://sample.example.com/auth/callback"},
				ServiceSecret:     "strong-service-secret",
			},
			wantErr: ErrInvalidReturnURL,
		},
		{
			name: "duplicate return url",
			request: ServiceProviderRegistration{
				ID:                "sample-client",
				DisplayName:       "Sample Client",
				AllowedReturnURLs: []string{"https://sample.example.com/auth/callback", "https://sample.example.com/auth/callback"},
				ServiceSecret:     "strong-service-secret",
			},
			wantErr: ErrDuplicateReturnURL,
		},
		{
			name: "weak secret",
			request: ServiceProviderRegistration{
				ID:                "sample-client",
				DisplayName:       "Sample Client",
				AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
				ServiceSecret:     "short",
			},
			wantErr: ErrWeakServiceSecret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestServiceProviderRegistrar().RegisterServiceProvider(context.Background(), tc.request)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RegisterServiceProvider error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestServiceProviderRegistrationHandlerRequiresAdminAuthentication(t *testing.T) {
	handler := NewServiceProviderRegistrationHandler(
		newTestServiceProviderRegistrar(),
		StaticAdminAuthenticator("admin-token"),
		ServiceProviderRegistrationHandlerOptions{},
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONServiceProviderRegistrationRequest("bad-token", ServiceProviderRegistrationRequest{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(response.Body.String(), "bad-token") || strings.Contains(response.Body.String(), "strong-service-secret") {
		t.Fatalf("response leaks sensitive data: %s", response.Body.String())
	}
}

func TestServiceProviderRegistrationHandlerReturnsMetadataWithoutSecretMaterial(t *testing.T) {
	handler := NewServiceProviderRegistrationHandler(
		newTestServiceProviderRegistrar(),
		StaticAdminAuthenticator("admin-token"),
		ServiceProviderRegistrationHandlerOptions{},
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newJSONServiceProviderRegistrationRequest("admin-token", ServiceProviderRegistrationRequest{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}))

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var body ServiceProviderRegistrationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("response JSON decode failed: %v", err)
	}
	if body.ID != "sample-client" || body.DisplayName != "Sample Client" || !body.Active {
		t.Fatalf("body = %#v", body)
	}
	if len(body.AllowedReturnURLs) != 1 || body.AllowedReturnURLs[0] != "https://sample.example.com/auth/callback" {
		t.Fatalf("allowedReturnUrls = %#v", body.AllowedReturnURLs)
	}
	responseText := response.Body.String()
	if strings.Contains(responseText, "strong-service-secret") || strings.Contains(responseText, "SecretHash") || strings.Contains(responseText, "secretHash") {
		t.Fatalf("response leaks secret material: %s", responseText)
	}
}

func TestServiceProviderRegistrationHandlerMapsDuplicateAndInvalidRequests(t *testing.T) {
	handler := NewServiceProviderRegistrationHandler(
		newTestServiceProviderRegistrar(),
		StaticAdminAuthenticator("admin-token"),
		ServiceProviderRegistrationHandlerOptions{},
	)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newJSONServiceProviderRegistrationRequest("admin-token", ServiceProviderRegistrationRequest{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusCreated)
	}

	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, newJSONServiceProviderRegistrationRequest("admin-token", ServiceProviderRegistrationRequest{
		ID:                "sample-client",
		DisplayName:       "Sample Client",
		AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", duplicate.Code, http.StatusConflict)
	}

	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, newJSONServiceProviderRegistrationRequest("admin-token", ServiceProviderRegistrationRequest{
		ID:                "other-client",
		DisplayName:       "Other Client",
		AllowedReturnURLs: []string{"http://other.example.com/auth/callback"},
		Active:            true,
		ServiceSecret:     "strong-service-secret",
	}))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}
}

func newTestServiceProviderRegistrar() *ServiceProviderRegistrationService {
	return NewServiceProviderRegistrationService(NewMemoryServiceProviderStore(nil), ServiceProviderRegistrationOptions{
		Clock: func() time.Time {
			return time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
		},
		SaltGenerator: func() ([]byte, error) {
			return []byte("service-salt"), nil
		},
		SecretIterations: 1000,
	})
}

func newJSONServiceProviderRegistrationRequest(adminToken string, payload ServiceProviderRegistrationRequest) *http.Request {
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/service-providers", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		request.Header.Set("Authorization", "Bearer "+adminToken)
	}
	return request
}
