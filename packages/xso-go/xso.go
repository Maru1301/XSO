package xso

import (
	"context"
	"time"

	"xso/packages/xso-go/config"
	"xso/packages/xso-go/session"
)

type Config = config.Config

type Client struct {
	config Config
}

func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = "xso_session"
	}

	return &Client{config: cfg}
}

func (c *Client) Config() Config {
	return c.config
}

func (c *Client) ValidateSession(_ context.Context, sessionID string) (session.ValidationResult, error) {
	if sessionID == "" {
		return session.ValidationResult{}, ErrUnauthorized()
	}

	// Placeholder until the gRPC validation boundary is implemented.
	return session.ValidationResult{
		User: session.User{
			UserID:      "local-dev",
			DisplayName: "Local Dev User",
		},
	}, nil
}

func ErrUnauthorized() error {
	return errorsUnauthorized
}

var errorsUnauthorized = errUnauthorized{}

type errUnauthorized struct{}

func (errUnauthorized) Error() string {
	return "unauthorized"
}
