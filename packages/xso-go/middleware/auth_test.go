package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	xso "xso/packages/xso-go"
	xsoerrors "xso/packages/xso-go/errors"
	"xso/packages/xso-go/session"
)

func TestAuthenticateRejectsMissingAndEmptySessionCookie(t *testing.T) {
	client := xso.NewClient(xso.Config{SessionCookieName: "xso_session"}, xso.WithSessionValidator(&stubValidator{
		result: session.ValidationResult{User: session.User{UserID: "user-1"}},
	}))
	handler := Authenticate(client)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing cookie status = %d, want %d", missing.Code, http.StatusUnauthorized)
	}

	emptyRequest := httptest.NewRequest(http.MethodGet, "/profile", nil)
	emptyRequest.AddCookie(&http.Cookie{Name: "xso_session", Value: ""})
	empty := httptest.NewRecorder()
	handler.ServeHTTP(empty, emptyRequest)
	if empty.Code != http.StatusUnauthorized {
		t.Fatalf("empty cookie status = %d, want %d", empty.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticateInjectsValidatedUserIntoRequestContext(t *testing.T) {
	client := xso.NewClient(xso.Config{SessionCookieName: "xso_session"}, xso.WithSessionValidator(&stubValidator{
		result: session.ValidationResult{
			User: session.User{
				UserID:      "user-1",
				DisplayName: "Ada Lovelace",
				Roles:       []string{"admin"},
				Groups:      []string{"engineering"},
				Permissions: []string{"profile:read"},
			},
		},
	}))
	handler := Authenticate(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := xso.UserFromContext(r.Context())
		if !ok {
			t.Fatal("missing user context")
		}
		if user.UserID != "user-1" || user.Permissions[0] != "profile:read" {
			t.Fatalf("user = %#v", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	request.AddCookie(&http.Cookie{Name: "xso_session", Value: "session-1"})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestAuthenticateMapsValidatorErrorsToUnauthorized(t *testing.T) {
	cases := []error{
		xsoerrors.ErrSessionExpired,
		xsoerrors.ErrInvalidToken,
		context.DeadlineExceeded,
		errors.New("backend unavailable"),
	}

	for _, validatorErr := range cases {
		t.Run(validatorErr.Error(), func(t *testing.T) {
			client := xso.NewClient(xso.Config{SessionCookieName: "xso_session"}, xso.WithSessionValidator(&stubValidator{
				err: validatorErr,
			}))
			handler := Authenticate(client)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodGet, "/profile", nil)
			request.AddCookie(&http.Cookie{Name: "xso_session", Value: "session-1"})
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if response.Body.String() != "unauthorized\n" {
				t.Fatalf("body = %q, want generic unauthorized", response.Body.String())
			}
		})
	}
}

type stubValidator struct {
	result session.ValidationResult
	err    error
}

func (v *stubValidator) ValidateSession(context.Context, session.Credential) (session.ValidationResult, error) {
	if v.err != nil {
		return session.ValidationResult{}, v.err
	}
	return v.result, nil
}
