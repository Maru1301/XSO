package xso

import (
	"context"
	"errors"
	"testing"
	"time"

	xsoerrors "xso/packages/xso-go/errors"
	"xso/packages/xso-go/session"
)

func TestClientValidateSessionRejectsEmptySessionWithoutCallingValidator(t *testing.T) {
	validator := &recordingSessionValidator{
		result: session.ValidationResult{
			User: session.User{UserID: "user-1"},
		},
	}
	client := NewClient(Config{}, WithSessionValidator(validator))

	_, err := client.ValidateSession(context.Background(), "")

	if !errors.Is(err, xsoerrors.ErrUnauthorized) {
		t.Fatalf("ValidateSession error = %v, want ErrUnauthorized", err)
	}
	if validator.called {
		t.Fatal("validator was called for an empty session")
	}
}

func TestClientValidateSessionRejectsMissingValidatorWithoutLocalDevUser(t *testing.T) {
	client := NewClient(Config{})

	_, err := client.ValidateSession(context.Background(), "session-1")

	if !errors.Is(err, xsoerrors.ErrUnauthorized) {
		t.Fatalf("ValidateSession error = %v, want ErrUnauthorized", err)
	}
}

func TestClientValidateSessionDelegatesToValidator(t *testing.T) {
	validator := &recordingSessionValidator{
		result: session.ValidationResult{
			User: session.User{
				UserID:      "user-1",
				EmployeeID:  "E1001",
				DisplayName: "Ada Lovelace",
				Roles:       []string{"admin"},
				Groups:      []string{"engineering"},
				Permissions: []string{"profile:read"},
			},
		},
	}
	client := NewClient(Config{}, WithSessionValidator(validator))

	result, err := client.ValidateSession(context.Background(), "session-1")

	if err != nil {
		t.Fatalf("ValidateSession returned error: %v", err)
	}
	if validator.credential.Token != "session-1" {
		t.Fatalf("credential = %#v", validator.credential)
	}
	if result.User.UserID != "user-1" || result.User.Permissions[0] != "profile:read" {
		t.Fatalf("result = %#v", result)
	}
}

func TestClientValidateSessionPropagatesTypedValidatorErrors(t *testing.T) {
	cases := []error{
		xsoerrors.ErrSessionExpired,
		xsoerrors.ErrInvalidToken,
		xsoerrors.ErrUnauthorized,
	}

	for _, wantErr := range cases {
		t.Run(wantErr.Error(), func(t *testing.T) {
			client := NewClient(Config{}, WithSessionValidator(&recordingSessionValidator{err: wantErr}))

			_, err := client.ValidateSession(context.Background(), "session-1")
			if !errors.Is(err, wantErr) {
				t.Fatalf("ValidateSession error = %v, want %v", err, wantErr)
			}
		})
	}
}

func TestClientValidateSessionRejectsMalformedValidatorResult(t *testing.T) {
	client := NewClient(Config{}, WithSessionValidator(&recordingSessionValidator{
		result: session.ValidationResult{},
	}))

	_, err := client.ValidateSession(context.Background(), "session-1")

	if !errors.Is(err, xsoerrors.ErrUnauthorized) {
		t.Fatalf("ValidateSession error = %v, want ErrUnauthorized", err)
	}
}

func TestClientValidateSessionAppliesTimeout(t *testing.T) {
	client := NewClient(Config{Timeout: time.Millisecond}, WithSessionValidator(session.ValidatorFunc(
		func(ctx context.Context, _ session.Credential) (session.ValidationResult, error) {
			<-ctx.Done()
			return session.ValidationResult{}, ctx.Err()
		},
	)))

	_, err := client.ValidateSession(context.Background(), "session-1")

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ValidateSession error = %v, want context deadline exceeded", err)
	}
}

type recordingSessionValidator struct {
	called     bool
	credential session.Credential
	result     session.ValidationResult
	err        error
}

func (v *recordingSessionValidator) ValidateSession(_ context.Context, credential session.Credential) (session.ValidationResult, error) {
	v.called = true
	v.credential = credential
	if v.err != nil {
		return session.ValidationResult{}, v.err
	}
	return v.result, nil
}
