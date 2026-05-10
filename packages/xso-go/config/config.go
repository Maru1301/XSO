package config

import "time"

type Config struct {
	Address           string
	Timeout           time.Duration
	RetryCount        int
	EnableTLS         bool
	ServiceName       string
	SessionCookieName string
}
