package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"xso/apps/xso-idp/internal/login"
)

func main() {
	loginDistDir := filepath.Clean("frontend/xso-login/dist")
	adminToken := os.Getenv("XSO_ADMIN_TOKEN")
	providerStore := login.NewMemoryServiceProviderStore(nil)
	serviceProviderRegistrar := login.NewServiceProviderRegistrationService(providerStore, login.ServiceProviderRegistrationOptions{})
	challengeService := login.NewChallengeService(
		providerStore,
		login.NewMemoryChallengeStore(),
		login.ChallengeServiceOptions{},
	)
	authenticator := login.NewMemoryCredentialAuthenticator(nil)
	serviceAuthenticator := login.NewMemoryServiceProviderAuthenticator(providerStore)
	sessionIssuer := login.NewLoginResultIssuer(
		login.NewMemoryIDPSessionStore(),
		login.NewMemoryLoginResultStore(),
		login.LoginResultIssuerOptions{},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/admin/service-providers", login.NewServiceProviderRegistrationHandler(
		serviceProviderRegistrar,
		login.StaticAdminAuthenticator(adminToken),
		login.ServiceProviderRegistrationHandlerOptions{},
	))
	mux.Handle("/login", login.NewLoginHandler(
		login.NewLoginPageHandler(challengeService, login.LoginPageHandlerOptions{
			DistDir: loginDistDir,
		}),
		login.NewLoginSubmitHandler(challengeService, authenticator, sessionIssuer, login.LoginSubmitHandlerOptions{}),
	))
	mux.Handle("/login/token", login.NewLoginResultExchangeHandler(sessionIssuer, serviceAuthenticator, login.LoginResultExchangeHandlerOptions{}))
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
