package xso

import (
	"context"

	"xso/packages/xso-go/session"
)

type userContextKey struct{}

func ContextWithUser(ctx context.Context, user session.User) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

func UserFromContext(ctx context.Context) (session.User, bool) {
	user, ok := ctx.Value(userContextKey{}).(session.User)
	return user, ok
}
