package errors

import stderrors "errors"

var (
	ErrUnauthorized   = stderrors.New("unauthorized")
	ErrSessionExpired = stderrors.New("session expired")
	ErrInvalidToken   = stderrors.New("invalid token")
)
