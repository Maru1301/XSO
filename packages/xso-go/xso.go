package xso

import (
	"context"
	"time"

	"xso/packages/xso-go/config"
	xsoerrors "xso/packages/xso-go/errors"
	"xso/packages/xso-go/session"
)

type Config = config.Config

type Client struct {
	config    Config
	validator session.Validator
}

type ClientOption func(*Client)

func WithSessionValidator(validator session.Validator) ClientOption {
	return func(c *Client) {
		c.validator = validator
	}
}

func NewClient(cfg Config, options ...ClientOption) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = "xso_session"
	}

	client := &Client{config: cfg}
	for _, option := range options {
		option(client)
	}

	return client
}

func (c *Client) Config() Config {
	return c.config
}

func (c *Client) ValidateSession(ctx context.Context, sessionID string) (session.ValidationResult, error) {
	if sessionID == "" {
		return session.ValidationResult{}, ErrUnauthorized()
	}
	if c.validator == nil {
		return session.ValidationResult{}, ErrUnauthorized()
	}

	validationCtx := ctx
	cancel := func() {}
	if c.config.Timeout > 0 {
		validationCtx, cancel = context.WithTimeout(ctx, c.config.Timeout)
	}
	defer cancel()

	result, err := c.validator.ValidateSession(validationCtx, session.Credential{Token: sessionID})
	if err != nil {
		return session.ValidationResult{}, err
	}
	if result.User.UserID == "" {
		return session.ValidationResult{}, ErrUnauthorized()
	}

	return result, nil
}

func ErrUnauthorized() error {
	return xsoerrors.ErrUnauthorized
}
