package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisChallengeStoreStoresLoadsAndConsumesChallengeOnce(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	store := NewRedisChallengeStore(client, RedisCacheOptions{
		KeyPrefix: "test",
		Clock:     func() time.Time { return now },
	})
	challenge := Challenge{
		ID:                "challenge-1",
		ServiceProviderID: "sample-client",
		ReturnURL:         "https://sample.example.com/auth/callback",
		CSRFToken:         "csrf-1",
		CreatedAt:         now,
		ExpiresAt:         now.Add(5 * time.Minute),
	}

	if err := store.SaveChallenge(context.Background(), challenge); err != nil {
		t.Fatalf("SaveChallenge returned error: %v", err)
	}

	got, ok, err := store.FindChallenge(context.Background(), "challenge-1")
	if err != nil {
		t.Fatalf("FindChallenge returned error: %v", err)
	}
	if !ok || got.ID != challenge.ID || got.ServiceProviderID != challenge.ServiceProviderID || got.CSRFToken != challenge.CSRFToken {
		t.Fatalf("challenge = %#v, ok = %v", got, ok)
	}

	if err := store.MarkChallengeUsed(context.Background(), "challenge-1"); err != nil {
		t.Fatalf("first MarkChallengeUsed returned error: %v", err)
	}
	got, ok, err = store.FindChallenge(context.Background(), "challenge-1")
	if err != nil {
		t.Fatalf("FindChallenge after consume returned error: %v", err)
	}
	if !ok || !got.Used {
		t.Fatalf("consumed challenge = %#v, ok = %v", got, ok)
	}

	err = store.MarkChallengeUsed(context.Background(), "challenge-1")
	if !errors.Is(err, ErrUsedChallenge) {
		t.Fatalf("second MarkChallengeUsed error = %v, want ErrUsedChallenge", err)
	}
}

func TestRedisIDPSessionStoreStoresLoadsAndDeletesSession(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	store := NewRedisIDPSessionStore(client, RedisCacheOptions{
		KeyPrefix: "test",
		Clock:     func() time.Time { return now },
	})
	session := IDPSession{
		ID:            "session-1",
		UserID:        "user-1",
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(8 * time.Hour),
		IdleExpiresAt: now.Add(30 * time.Minute),
	}

	if err := store.SaveIDPSession(context.Background(), session); err != nil {
		t.Fatalf("SaveIDPSession returned error: %v", err)
	}
	got, ok, err := store.FindIDPSession(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("FindIDPSession returned error: %v", err)
	}
	if !ok || got.ID != session.ID || got.UserID != session.UserID || !got.IdleExpiresAt.Equal(session.IdleExpiresAt) {
		t.Fatalf("session = %#v, ok = %v", got, ok)
	}

	if err := store.DeleteIDPSession(context.Background(), "session-1"); err != nil {
		t.Fatalf("DeleteIDPSession returned error: %v", err)
	}
	_, ok, err = store.FindIDPSession(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("FindIDPSession after delete returned error: %v", err)
	}
	if ok {
		t.Fatal("FindIDPSession after delete ok = true, want false")
	}
}

func TestRedisReplayCacheRejectsDuplicateMarker(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	cache := NewRedisReplayCache(client, RedisCacheOptions{KeyPrefix: "test"})
	digest := []byte("code-digest")

	if err := cache.MarkUsed(context.Background(), "login-result", digest, 5*time.Minute); err != nil {
		t.Fatalf("first MarkUsed returned error: %v", err)
	}
	err := cache.MarkUsed(context.Background(), "login-result", digest, 5*time.Minute)
	if !errors.Is(err, ErrReplayAlreadyUsed) {
		t.Fatalf("second MarkUsed error = %v, want ErrReplayAlreadyUsed", err)
	}
}
