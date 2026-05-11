package login

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrReplayAlreadyUsed = errors.New("replay already used")

type RedisCacheOptions struct {
	KeyPrefix string
	Clock     func() time.Time
}

type redisCache struct {
	client redis.Cmdable
	prefix string
	clock  func() time.Time
}

func newRedisCache(client redis.Cmdable, options RedisCacheOptions) redisCache {
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = "xso:v1"
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return redisCache{client: client, prefix: prefix, clock: clock}
}

func (c redisCache) key(parts ...string) string {
	key := c.prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

type RedisChallengeStore struct {
	redisCache
}

func NewRedisChallengeStore(client redis.Cmdable, options RedisCacheOptions) *RedisChallengeStore {
	return &RedisChallengeStore{redisCache: newRedisCache(client, options)}
}

func (s *RedisChallengeStore) SaveChallenge(ctx context.Context, challenge Challenge) error {
	ttl := time.Until(challenge.ExpiresAt)
	if !challenge.CreatedAt.IsZero() {
		ttl = challenge.ExpiresAt.Sub(s.clock())
	}
	if ttl <= 0 {
		return ErrExpiredChallenge
	}

	payload, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	ok, err := s.client.SetNX(ctx, s.key("challenge", challenge.ID), payload, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrDuplicateChallenge
	}
	return nil
}

func (s *RedisChallengeStore) FindChallenge(ctx context.Context, id string) (Challenge, bool, error) {
	payload, err := s.client.Get(ctx, s.key("challenge", id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, err
	}

	var challenge Challenge
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return Challenge{}, false, err
	}
	if exists, err := s.client.Exists(ctx, s.key("challenge-used", id)).Result(); err != nil {
		return Challenge{}, false, err
	} else if exists > 0 {
		challenge.Used = true
	}

	return challenge, true, nil
}

func (s *RedisChallengeStore) MarkChallengeUsed(ctx context.Context, id string) error {
	challenge, ok, err := s.FindChallenge(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnknownChallenge
	}

	ttl := challenge.ExpiresAt.Sub(s.clock()) + time.Minute
	if ttl <= 0 {
		ttl = time.Minute
	}
	used, err := s.client.SetNX(ctx, s.key("challenge-used", id), "1", ttl).Result()
	if err != nil {
		return err
	}
	if !used {
		return ErrUsedChallenge
	}

	return nil
}

type RedisIDPSessionStore struct {
	redisCache
}

func NewRedisIDPSessionStore(client redis.Cmdable, options RedisCacheOptions) *RedisIDPSessionStore {
	return &RedisIDPSessionStore{redisCache: newRedisCache(client, options)}
}

func (s *RedisIDPSessionStore) SaveIDPSession(ctx context.Context, session IDPSession) error {
	ttl := session.IdleExpiresAt.Sub(s.clock())
	absoluteTTL := session.ExpiresAt.Sub(s.clock())
	if absoluteTTL < ttl {
		ttl = absoluteTTL
	}
	if ttl <= 0 {
		return ErrExpiredChallenge
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.key("session", session.ID), payload, ttl).Err()
}

func (s *RedisIDPSessionStore) FindIDPSession(ctx context.Context, id string) (IDPSession, bool, error) {
	payload, err := s.client.Get(ctx, s.key("session", id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return IDPSession{}, false, nil
	}
	if err != nil {
		return IDPSession{}, false, err
	}

	var session IDPSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return IDPSession{}, false, err
	}
	return session, true, nil
}

func (s *RedisIDPSessionStore) DeleteIDPSession(ctx context.Context, id string) error {
	return s.client.Del(ctx, s.key("session", id)).Err()
}

type RedisReplayCache struct {
	redisCache
}

func NewRedisReplayCache(client redis.Cmdable, options RedisCacheOptions) *RedisReplayCache {
	return &RedisReplayCache{redisCache: newRedisCache(client, options)}
}

func (c *RedisReplayCache) MarkUsed(ctx context.Context, namespace string, digest []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return ErrExpiredChallenge
	}
	ok, err := c.client.SetNX(ctx, c.key(namespace+"-used", hex.EncodeToString(digest)), "1", ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrReplayAlreadyUsed
	}
	return nil
}
