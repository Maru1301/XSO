package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	xso "xso/packages/xso-go"
	"xso/packages/xso-go/middleware"
	"xso/packages/xso-go/session"
)

func main() {
	client := xso.NewClient(xso.Config{
		Address:           "localhost:50051",
		Timeout:           3 * time.Second,
		ServiceName:       "sample-client",
		SessionCookieName: "xso_session",
	}, xso.WithSessionValidator(sampleValidator{}))

	mux := http.NewServeMux()
	mux.Handle("/profile", middleware.Authenticate(client)(http.HandlerFunc(profileHandler)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Println("sample-client listening on http://localhost:8081")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

type sampleValidator struct{}

func (sampleValidator) ValidateSession(_ context.Context, credential session.Credential) (session.ValidationResult, error) {
	if credential.Token == "" {
		return session.ValidationResult{}, xso.ErrUnauthorized()
	}

	return session.ValidationResult{
		User: session.User{
			UserID:      "local-dev",
			DisplayName: "Local Dev User",
		},
	}, nil
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := xso.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "missing user context", http.StatusInternalServerError)
		return
	}

	_, _ = fmt.Fprintf(w, "hello %s\n", user.DisplayName)
}
