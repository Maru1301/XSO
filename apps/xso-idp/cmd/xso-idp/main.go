package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"xso/apps/xso-idp/internal/login"
)

func main() {
	loginDistDir := filepath.Clean("frontend/xso-login/dist")
	adminToken := os.Getenv("XSO_ADMIN_TOKEN")

	var providerStore login.ServiceProviderRegistry = login.NewMemoryServiceProviderStore(nil)
	var challengeStore login.ChallengeStore = login.NewMemoryChallengeStore()
	var authenticator login.LoginAuthenticator = login.NewMemoryCredentialAuthenticator(nil)
	var sessionStore login.IDPSessionStore = login.NewMemoryIDPSessionStore()
	var resultStore login.LoginResultStore = login.NewMemoryLoginResultStore()

	if databaseURL := os.Getenv("XSO_DATABASE_URL"); databaseURL != "" {
		db, err := sql.Open("postgres", databaseURL)
		if err != nil {
			panic(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			panic(err)
		}

		postgresStore := login.NewPostgreSQLStore(db)
		providerStore = postgresStore
		authenticator = login.NewPostgreSQLCredentialAuthenticator(db)
		sessionStore = postgresStore
		resultStore = postgresStore
	}

	if redisAddr := os.Getenv("XSO_REDIS_ADDR"); redisAddr != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: os.Getenv("XSO_REDIS_PASSWORD"),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			panic(err)
		}

		challengeStore = login.NewRedisChallengeStore(redisClient, login.RedisCacheOptions{})
		sessionStore = login.NewCachedIDPSessionStore(sessionStore, login.NewRedisIDPSessionStore(redisClient, login.RedisCacheOptions{}))
	}

	serviceProviderRegistrar := login.NewServiceProviderRegistrationService(providerStore, login.ServiceProviderRegistrationOptions{})
	challengeService := login.NewChallengeService(
		providerStore,
		challengeStore,
		login.ChallengeServiceOptions{},
	)
	serviceAuthenticator := login.NewMemoryServiceProviderAuthenticator(providerStore)
	sessionIssuer := login.NewLoginResultIssuer(
		sessionStore,
		resultStore,
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
