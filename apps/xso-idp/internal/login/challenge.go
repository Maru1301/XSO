package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrMissingChallenge        = errors.New("missing challenge")
	ErrUnknownChallenge        = errors.New("unknown challenge")
	ErrExpiredChallenge        = errors.New("expired challenge")
	ErrUsedChallenge           = errors.New("used challenge")
	ErrDuplicateChallenge      = errors.New("duplicate challenge")
	ErrUnknownServiceProvider  = errors.New("unknown service provider")
	ErrInactiveServiceProvider = errors.New("inactive service provider")
	ErrInvalidReturnURL        = errors.New("invalid return url")
)

type Challenge struct {
	ID                string
	ServiceProviderID string
	ReturnURL         string
	ExpiresAt         time.Time
	Used              bool
	CreatedAt         time.Time
	CSRFToken         string
}

type ServiceProvider struct {
	ID                string
	DisplayName       string
	AllowedReturnURLs []string
	Active            bool
}

type ServiceProviderStore interface {
	FindServiceProvider(ctx context.Context, id string) (ServiceProvider, bool, error)
}

type ChallengeStore interface {
	SaveChallenge(ctx context.Context, challenge Challenge) error
	FindChallenge(ctx context.Context, id string) (Challenge, bool, error)
	MarkChallengeUsed(ctx context.Context, id string) error
}

type TokenGenerator func() (string, error)

type ChallengeServiceOptions struct {
	TTL           time.Duration
	Clock         func() time.Time
	IDGenerator   TokenGenerator
	CSRFGenerator TokenGenerator
}

type ChallengeService struct {
	providers  ServiceProviderStore
	challenges ChallengeStore
	ttl        time.Duration
	clock      func() time.Time
	newID      TokenGenerator
	newCSRF    TokenGenerator
}

func NewChallengeService(providers ServiceProviderStore, challenges ChallengeStore, options ChallengeServiceOptions) *ChallengeService {
	ttl := options.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}

	newID := options.IDGenerator
	if newID == nil {
		newID = secureToken
	}

	newCSRF := options.CSRFGenerator
	if newCSRF == nil {
		newCSRF = secureToken
	}

	return &ChallengeService{
		providers:  providers,
		challenges: challenges,
		ttl:        ttl,
		clock:      clock,
		newID:      newID,
		newCSRF:    newCSRF,
	}
}

func (s *ChallengeService) CreateChallenge(ctx context.Context, serviceProviderID string, returnURL string) (Challenge, error) {
	provider, err := s.validateServiceProvider(ctx, serviceProviderID)
	if err != nil {
		return Challenge{}, err
	}
	if !isAllowedReturnURL(provider, returnURL) {
		return Challenge{}, ErrInvalidReturnURL
	}

	id, err := s.newID()
	if err != nil {
		return Challenge{}, err
	}
	csrf, err := s.newCSRF()
	if err != nil {
		return Challenge{}, err
	}

	now := s.clock()
	challenge := Challenge{
		ID:                id,
		ServiceProviderID: provider.ID,
		ReturnURL:         returnURL,
		ExpiresAt:         now.Add(s.ttl),
		CreatedAt:         now,
		CSRFToken:         csrf,
	}

	if err := s.challenges.SaveChallenge(ctx, challenge); err != nil {
		return Challenge{}, err
	}

	return challenge, nil
}

func (s *ChallengeService) ValidateChallenge(ctx context.Context, id string) (Challenge, error) {
	if strings.TrimSpace(id) == "" {
		return Challenge{}, ErrMissingChallenge
	}

	challenge, ok, err := s.challenges.FindChallenge(ctx, id)
	if err != nil {
		return Challenge{}, err
	}
	if !ok {
		return Challenge{}, ErrUnknownChallenge
	}
	if challenge.Used {
		return Challenge{}, ErrUsedChallenge
	}
	if !s.clock().Before(challenge.ExpiresAt) {
		return Challenge{}, ErrExpiredChallenge
	}

	provider, err := s.validateServiceProvider(ctx, challenge.ServiceProviderID)
	if err != nil {
		return Challenge{}, err
	}
	if !isAllowedReturnURL(provider, challenge.ReturnURL) {
		return Challenge{}, ErrInvalidReturnURL
	}

	return challenge, nil
}

func (s *ChallengeService) MarkChallengeUsed(ctx context.Context, id string) error {
	return s.challenges.MarkChallengeUsed(ctx, id)
}

func (s *ChallengeService) validateServiceProvider(ctx context.Context, id string) (ServiceProvider, error) {
	provider, ok, err := s.providers.FindServiceProvider(ctx, id)
	if err != nil {
		return ServiceProvider{}, err
	}
	if !ok {
		return ServiceProvider{}, ErrUnknownServiceProvider
	}
	if !provider.Active {
		return ServiceProvider{}, ErrInactiveServiceProvider
	}

	return provider, nil
}

func isAllowedReturnURL(provider ServiceProvider, returnURL string) bool {
	parsed, err := url.ParseRequestURI(returnURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	for _, allowed := range provider.AllowedReturnURLs {
		if returnURL == allowed {
			return true
		}
	}

	return false
}

func secureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type MemoryServiceProviderStore struct {
	mu        sync.RWMutex
	providers map[string]ServiceProvider
}

func NewMemoryServiceProviderStore(providers []ServiceProvider) *MemoryServiceProviderStore {
	store := &MemoryServiceProviderStore{
		providers: make(map[string]ServiceProvider, len(providers)),
	}
	for _, provider := range providers {
		store.providers[provider.ID] = provider
	}

	return store
}

func (s *MemoryServiceProviderStore) FindServiceProvider(_ context.Context, id string) (ServiceProvider, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	provider, ok := s.providers[id]
	return provider, ok, nil
}

type MemoryChallengeStore struct {
	mu         sync.RWMutex
	challenges map[string]Challenge
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{
		challenges: make(map[string]Challenge),
	}
}

func (s *MemoryChallengeStore) SaveChallenge(_ context.Context, challenge Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.challenges[challenge.ID]; exists {
		return ErrDuplicateChallenge
	}

	s.challenges[challenge.ID] = challenge
	return nil
}

func (s *MemoryChallengeStore) FindChallenge(_ context.Context, id string) (Challenge, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	challenge, ok := s.challenges[id]
	return challenge, ok, nil
}

func (s *MemoryChallengeStore) MarkChallengeUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, ok := s.challenges[id]
	if !ok {
		return ErrUnknownChallenge
	}
	challenge.Used = true
	s.challenges[id] = challenge

	return nil
}
