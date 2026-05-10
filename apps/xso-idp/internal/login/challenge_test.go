package login

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestChallengeServiceCreateValidChallenge(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)

	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}

	if challenge.ID != "challenge-1" {
		t.Fatalf("challenge.ID = %q, want challenge-1", challenge.ID)
	}
	if challenge.ServiceProviderID != "sample-client" {
		t.Fatalf("challenge.ServiceProviderID = %q, want sample-client", challenge.ServiceProviderID)
	}
	if challenge.ReturnURL != "https://sample.example.com/auth/callback" {
		t.Fatalf("challenge.ReturnURL = %q", challenge.ReturnURL)
	}
	if challenge.CreatedAt != now {
		t.Fatalf("challenge.CreatedAt = %v, want %v", challenge.CreatedAt, now)
	}
	if challenge.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("challenge.ExpiresAt = %v, want %v", challenge.ExpiresAt, now.Add(5*time.Minute))
	}
	if challenge.CSRFToken == "" {
		t.Fatal("challenge.CSRFToken is empty")
	}
	if challenge.Used {
		t.Fatal("challenge should not be marked used when created")
	}
}

func TestChallengeServiceCreateRejectsUnknownServiceProvider(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.CreateChallenge(context.Background(), "missing-client", "https://sample.example.com/auth/callback")
	if !errors.Is(err, ErrUnknownServiceProvider) {
		t.Fatalf("CreateChallenge error = %v, want ErrUnknownServiceProvider", err)
	}
}

func TestChallengeServiceCreateRejectsInactiveServiceProvider(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.CreateChallenge(context.Background(), "disabled-client", "https://disabled.example.com/auth/callback")
	if !errors.Is(err, ErrInactiveServiceProvider) {
		t.Fatalf("CreateChallenge error = %v, want ErrInactiveServiceProvider", err)
	}
}

func TestChallengeServiceCreateRejectsInvalidReturnURL(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.CreateChallenge(context.Background(), "sample-client", "https://attacker.example.com/callback")
	if !errors.Is(err, ErrInvalidReturnURL) {
		t.Fatalf("CreateChallenge error = %v, want ErrInvalidReturnURL", err)
	}
}

func TestChallengeServiceCreateRejectsMalformedReturnURL(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.CreateChallenge(context.Background(), "sample-client", "/local/path")
	if !errors.Is(err, ErrInvalidReturnURL) {
		t.Fatalf("CreateChallenge error = %v, want ErrInvalidReturnURL", err)
	}
}

func TestChallengeServiceCreateRejectsDuplicateChallengeID(t *testing.T) {
	service := newTestChallengeService(time.Now())

	if _, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback"); err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}

	_, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if !errors.Is(err, ErrDuplicateChallenge) {
		t.Fatalf("CreateChallenge error = %v, want ErrDuplicateChallenge", err)
	}
}

func TestChallengeServiceValidateRejectsMissingChallengeID(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.ValidateChallenge(context.Background(), "")
	if !errors.Is(err, ErrMissingChallenge) {
		t.Fatalf("ValidateChallenge error = %v, want ErrMissingChallenge", err)
	}
}

func TestChallengeServiceValidateRejectsUnknownChallenge(t *testing.T) {
	service := newTestChallengeService(time.Now())

	_, err := service.ValidateChallenge(context.Background(), "missing-challenge")
	if !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("ValidateChallenge error = %v, want ErrUnknownChallenge", err)
	}
}

func TestChallengeServiceValidateRejectsExpiredChallenge(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	service := newTestChallengeService(now)

	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}

	service.clock = func() time.Time {
		return now.Add(5*time.Minute + time.Second)
	}

	_, err = service.ValidateChallenge(context.Background(), challenge.ID)
	if !errors.Is(err, ErrExpiredChallenge) {
		t.Fatalf("ValidateChallenge error = %v, want ErrExpiredChallenge", err)
	}
}

func TestChallengeServiceValidateRejectsReusedChallenge(t *testing.T) {
	service := newTestChallengeService(time.Now())

	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	if err := service.MarkChallengeUsed(context.Background(), challenge.ID); err != nil {
		t.Fatalf("MarkChallengeUsed returned error: %v", err)
	}

	_, err = service.ValidateChallenge(context.Background(), challenge.ID)
	if !errors.Is(err, ErrUsedChallenge) {
		t.Fatalf("ValidateChallenge error = %v, want ErrUsedChallenge", err)
	}
}

func TestChallengeServiceValidateRejectsChallengeForInactiveServiceProvider(t *testing.T) {
	service := newTestChallengeService(time.Now())

	challenge, err := service.CreateChallenge(context.Background(), "sample-client", "https://sample.example.com/auth/callback")
	if err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	providers := service.providers.(*MemoryServiceProviderStore)
	provider := providers.providers["sample-client"]
	provider.Active = false
	providers.providers["sample-client"] = provider

	_, err = service.ValidateChallenge(context.Background(), challenge.ID)
	if !errors.Is(err, ErrInactiveServiceProvider) {
		t.Fatalf("ValidateChallenge error = %v, want ErrInactiveServiceProvider", err)
	}
}

func newTestChallengeService(now time.Time) *ChallengeService {
	providers := NewMemoryServiceProviderStore([]ServiceProvider{
		{
			ID:                "sample-client",
			DisplayName:       "Sample Client",
			Active:            true,
			AllowedReturnURLs: []string{"https://sample.example.com/auth/callback"},
		},
		{
			ID:                "disabled-client",
			DisplayName:       "Disabled Client",
			Active:            false,
			AllowedReturnURLs: []string{"https://disabled.example.com/auth/callback"},
		},
	})

	service := NewChallengeService(providers, NewMemoryChallengeStore(), ChallengeServiceOptions{
		TTL: 5 * time.Minute,
		Clock: func() time.Time {
			return now
		},
		IDGenerator:   fixedGenerator("challenge-1"),
		CSRFGenerator: fixedGenerator("csrf-1"),
	})
	service.providers = providers

	return service
}

func fixedGenerator(value string) TokenGenerator {
	return func() (string, error) {
		return value, nil
	}
}
