package login

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnsupportedPasswordHash           = errors.New("unsupported password hash")
	ErrInvalidServiceProviderCredentials = errors.New("invalid service provider credentials")
	ErrUnknownLoginResultCode            = errors.New("unknown login result code")
	ErrLoginResultCodeUsed               = errors.New("login result code used")
	ErrLoginResultCodeExpired            = errors.New("login result code expired")
	ErrLoginResultAudienceMismatch       = errors.New("login result audience mismatch")
)

const pbkdf2SHA256Algorithm = "pbkdf2-sha256"

type PasswordHash struct {
	Algorithm  string
	Salt       []byte
	Iterations int
	Key        []byte
}

func NewPBKDF2PasswordHash(password string, salt []byte, iterations int, keyLength int) (PasswordHash, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLength)
	if err != nil {
		return PasswordHash{}, err
	}

	return PasswordHash{
		Algorithm:  pbkdf2SHA256Algorithm,
		Salt:       append([]byte(nil), salt...),
		Iterations: iterations,
		Key:        key,
	}, nil
}

type UserAccount struct {
	ID           string
	DisplayName  string
	Identifiers  []string
	PasswordHash PasswordHash
	Disabled     bool
	Locked       bool
}

type MemoryCredentialAuthenticator struct {
	mu       sync.RWMutex
	accounts map[string]UserAccount
}

func NewMemoryCredentialAuthenticator(accounts []UserAccount) *MemoryCredentialAuthenticator {
	authenticator := &MemoryCredentialAuthenticator{
		accounts: make(map[string]UserAccount),
	}
	for _, account := range accounts {
		for _, identifier := range account.Identifiers {
			authenticator.accounts[normalizeIdentifier(identifier)] = account
		}
	}

	return authenticator
}

func (a *MemoryCredentialAuthenticator) Authenticate(ctx context.Context, credentials LoginCredentials) (LoginUser, error) {
	select {
	case <-ctx.Done():
		return LoginUser{}, ctx.Err()
	default:
	}

	identifier := normalizeIdentifier(credentials.Identifier)
	if identifier == "" || credentials.Password == "" {
		return LoginUser{}, ErrInvalidCredentials
	}

	a.mu.RLock()
	account, ok := a.accounts[identifier]
	a.mu.RUnlock()
	if !ok {
		return LoginUser{}, ErrInvalidCredentials
	}
	if err := verifyPasswordHash(credentials.Password, account.PasswordHash); err != nil {
		if errors.Is(err, ErrUnsupportedPasswordHash) {
			return LoginUser{}, err
		}
		return LoginUser{}, ErrInvalidCredentials
	}
	if account.Disabled {
		return LoginUser{}, ErrUserDisabled
	}
	if account.Locked {
		return LoginUser{}, ErrUserLocked
	}

	return LoginUser{
		ID:          account.ID,
		DisplayName: account.DisplayName,
	}, nil
}

func verifyPasswordHash(password string, expected PasswordHash) error {
	if expected.Algorithm != pbkdf2SHA256Algorithm || expected.Iterations <= 0 || len(expected.Salt) == 0 || len(expected.Key) == 0 {
		return ErrUnsupportedPasswordHash
	}

	actual, err := pbkdf2.Key(sha256.New, password, expected.Salt, expected.Iterations, len(expected.Key))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(actual, expected.Key) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

func normalizeIdentifier(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

type ServiceProviderCredentials struct {
	ServiceProviderID string
	Secret            string
}

type ServiceProviderAuthenticator interface {
	AuthenticateServiceProvider(ctx context.Context, credentials ServiceProviderCredentials) (ServiceProvider, error)
}

type MemoryServiceProviderAuthenticator struct {
	providers ServiceProviderStore
}

func NewMemoryServiceProviderAuthenticator(providers ServiceProviderStore) *MemoryServiceProviderAuthenticator {
	return &MemoryServiceProviderAuthenticator{providers: providers}
}

func (a *MemoryServiceProviderAuthenticator) AuthenticateServiceProvider(ctx context.Context, credentials ServiceProviderCredentials) (ServiceProvider, error) {
	serviceProviderID := strings.TrimSpace(credentials.ServiceProviderID)
	if serviceProviderID == "" || credentials.Secret == "" {
		return ServiceProvider{}, ErrInvalidServiceProviderCredentials
	}

	provider, ok, err := a.providers.FindServiceProvider(ctx, serviceProviderID)
	if err != nil {
		return ServiceProvider{}, err
	}
	if !ok || !provider.Active {
		return ServiceProvider{}, ErrInvalidServiceProviderCredentials
	}
	if err := verifyPasswordHash(credentials.Secret, provider.SecretHash); err != nil {
		if errors.Is(err, ErrUnsupportedPasswordHash) || errors.Is(err, ErrInvalidCredentials) {
			return ServiceProvider{}, ErrInvalidServiceProviderCredentials
		}
		return ServiceProvider{}, err
	}

	return provider, nil
}

type IDPSession struct {
	ID            string
	UserID        string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

type IDPSessionStore interface {
	SaveIDPSession(ctx context.Context, session IDPSession) error
	FindIDPSession(ctx context.Context, id string) (IDPSession, bool, error)
}

type LoginResult struct {
	Code              string
	AccessToken       string
	UserID            string
	ServiceProviderID string
	ChallengeID       string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	Used              bool
}

type LoginResultStore interface {
	SaveLoginResult(ctx context.Context, result LoginResult) error
	FindLoginResult(ctx context.Context, code string) (LoginResult, bool, error)
	MarkLoginResultUsed(ctx context.Context, code string) error
}

type LoginResultIssuerOptions struct {
	Clock                func() time.Time
	SessionIDGenerator   TokenGenerator
	CodeGenerator        TokenGenerator
	AccessTokenGenerator TokenGenerator
	SessionAbsoluteTTL   time.Duration
	SessionIdleTTL       time.Duration
	LoginResultTTL       time.Duration
	SessionCookieName    string
}

type LoginResultIssuer struct {
	sessions       IDPSessionStore
	results        LoginResultStore
	clock          func() time.Time
	newSessionID   TokenGenerator
	newCode        TokenGenerator
	newAccessToken TokenGenerator
	sessionTTL     time.Duration
	idleTTL        time.Duration
	resultTTL      time.Duration
	cookieName     string
	cookieSecure   bool
}

func NewLoginResultIssuer(sessions IDPSessionStore, results LoginResultStore, options LoginResultIssuerOptions) *LoginResultIssuer {
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	sessionIDGenerator := options.SessionIDGenerator
	if sessionIDGenerator == nil {
		sessionIDGenerator = secureToken
	}
	codeGenerator := options.CodeGenerator
	if codeGenerator == nil {
		codeGenerator = secureToken
	}
	accessTokenGenerator := options.AccessTokenGenerator
	if accessTokenGenerator == nil {
		accessTokenGenerator = secureToken
	}
	sessionTTL := options.SessionAbsoluteTTL
	if sessionTTL == 0 {
		sessionTTL = 8 * time.Hour
	}
	idleTTL := options.SessionIdleTTL
	if idleTTL == 0 {
		idleTTL = 30 * time.Minute
	}
	resultTTL := options.LoginResultTTL
	if resultTTL == 0 {
		resultTTL = 5 * time.Minute
	}
	cookieName := options.SessionCookieName
	if cookieName == "" {
		cookieName = "xso_idp_session"
	}

	return &LoginResultIssuer{
		sessions:       sessions,
		results:        results,
		clock:          clock,
		newSessionID:   sessionIDGenerator,
		newCode:        codeGenerator,
		newAccessToken: accessTokenGenerator,
		sessionTTL:     sessionTTL,
		idleTTL:        idleTTL,
		resultTTL:      resultTTL,
		cookieName:     cookieName,
		cookieSecure:   true,
	}
}

func (i *LoginResultIssuer) IssueSession(ctx context.Context, request LoginSessionRequest) (LoginSession, error) {
	now := i.clock()
	sessionID, err := i.newSessionID()
	if err != nil {
		return LoginSession{}, err
	}
	code, err := i.newCode()
	if err != nil {
		return LoginSession{}, err
	}
	accessToken, err := i.newAccessToken()
	if err != nil {
		return LoginSession{}, err
	}

	session := IDPSession{
		ID:            sessionID,
		UserID:        request.User.ID,
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(i.sessionTTL),
		IdleExpiresAt: now.Add(i.idleTTL),
	}
	if err := i.sessions.SaveIDPSession(ctx, session); err != nil {
		return LoginSession{}, err
	}

	result := LoginResult{
		Code:              code,
		AccessToken:       accessToken,
		UserID:            request.User.ID,
		ServiceProviderID: request.ServiceProviderID,
		ChallengeID:       request.ChallengeID,
		IssuedAt:          now,
		ExpiresAt:         now.Add(i.resultTTL),
	}
	if err := i.results.SaveLoginResult(ctx, result); err != nil {
		return LoginSession{}, err
	}

	redirectURL, err := appendLoginResultCode(request.ReturnURL, code)
	if err != nil {
		return LoginSession{}, err
	}

	return LoginSession{
		Cookies: []http.Cookie{{
			Name:     i.cookieName,
			Value:    sessionID,
			Path:     "/",
			Expires:  session.ExpiresAt,
			MaxAge:   int(i.sessionTTL.Seconds()),
			HttpOnly: true,
			Secure:   i.cookieSecure,
			SameSite: http.SameSiteLaxMode,
		}},
		RedirectURL: redirectURL,
	}, nil
}

func (i *LoginResultIssuer) ExchangeLoginResultCode(ctx context.Context, code string) (LoginResult, error) {
	return i.exchangeLoginResultCode(ctx, "", code)
}

func (i *LoginResultIssuer) ExchangeLoginResultCodeForService(ctx context.Context, serviceProviderID string, code string) (LoginResult, error) {
	return i.exchangeLoginResultCode(ctx, strings.TrimSpace(serviceProviderID), code)
}

func (i *LoginResultIssuer) exchangeLoginResultCode(ctx context.Context, serviceProviderID string, code string) (LoginResult, error) {
	result, ok, err := i.results.FindLoginResult(ctx, code)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		return LoginResult{}, ErrUnknownLoginResultCode
	}
	if result.Used {
		return LoginResult{}, ErrLoginResultCodeUsed
	}
	if !i.clock().Before(result.ExpiresAt) {
		return LoginResult{}, ErrLoginResultCodeExpired
	}
	if serviceProviderID != "" && result.ServiceProviderID != serviceProviderID {
		return LoginResult{}, ErrLoginResultAudienceMismatch
	}
	if err := i.results.MarkLoginResultUsed(ctx, code); err != nil {
		return LoginResult{}, err
	}
	result.Used = true

	return result, nil
}

func appendLoginResultCode(returnURL string, code string) (string, error) {
	parsed, err := url.Parse(returnURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("code", code)
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

type MemoryIDPSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]IDPSession
}

func NewMemoryIDPSessionStore() *MemoryIDPSessionStore {
	return &MemoryIDPSessionStore{sessions: make(map[string]IDPSession)}
}

func (s *MemoryIDPSessionStore) SaveIDPSession(_ context.Context, session IDPSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryIDPSessionStore) FindIDPSession(_ context.Context, id string) (IDPSession, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[id]
	return session, ok, nil
}

type MemoryLoginResultStore struct {
	mu      sync.RWMutex
	results map[string]LoginResult
}

func NewMemoryLoginResultStore() *MemoryLoginResultStore {
	return &MemoryLoginResultStore{results: make(map[string]LoginResult)}
}

func (s *MemoryLoginResultStore) SaveLoginResult(_ context.Context, result LoginResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.results[result.Code] = result
	return nil
}

func (s *MemoryLoginResultStore) FindLoginResult(_ context.Context, code string) (LoginResult, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result, ok := s.results[code]
	return result, ok, nil
}

func (s *MemoryLoginResultStore) MarkLoginResultUsed(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, ok := s.results[code]
	if !ok {
		return ErrUnknownLoginResultCode
	}
	if result.Used {
		return ErrLoginResultCodeUsed
	}
	result.Used = true
	s.results[code] = result

	return nil
}
