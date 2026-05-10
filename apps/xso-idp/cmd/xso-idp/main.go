package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"xso/apps/xso-idp/internal/login"
)

func main() {
	loginDistDir := filepath.Clean("frontend/xso-login/dist")
	challengeService := login.NewChallengeService(
		login.NewMemoryServiceProviderStore(nil),
		login.NewMemoryChallengeStore(),
		login.ChallengeServiceOptions{},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/login", login.NewLoginPageHandler(challengeService, login.LoginPageHandlerOptions{
		DistDir: loginDistDir,
	}))
	mux.Handle("/login-assets/", login.NewLoginAssetHandler(loginDistDir))

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Println("xso-idp listening on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
