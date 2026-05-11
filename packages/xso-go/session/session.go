package session

import "context"

type Credential struct {
	Token string
}

type User struct {
	UserID      string
	EmployeeID  string
	DisplayName string
	Roles       []string
	Groups      []string
	Permissions []string
}

type ValidationResult struct {
	User User
}

type Validator interface {
	ValidateSession(ctx context.Context, credential Credential) (ValidationResult, error)
}

type ValidatorFunc func(ctx context.Context, credential Credential) (ValidationResult, error)

func (f ValidatorFunc) ValidateSession(ctx context.Context, credential Credential) (ValidationResult, error) {
	return f(ctx, credential)
}
