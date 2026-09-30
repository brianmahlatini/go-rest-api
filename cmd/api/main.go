// Command api runs the tasks REST API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brianmahlatini/go-rest-api/internal/api"
	"github.com/brianmahlatini/go-rest-api/internal/auth"
	"github.com/brianmahlatini/go-rest-api/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		log.Error("JWT_SECRET must be set to at least 32 bytes (e.g. openssl rand -hex 32)")
		os.Exit(1)
	}
	st := store.NewMemory()
	hasher := auth.Hasher{Iterations: auth.DefaultIterations}

	// Optional demo admin (fake data) for local development.
	if email, pw := os.Getenv("SEED_ADMIN_EMAIL"), os.Getenv("SEED_ADMIN_PASSWORD"); email != "" && len(pw) >= 12 {
		h, err := hasher.Hash(pw)
		if err == nil {
			_ = st.CreateUser(store.User{ID: "usr_admin", Email: strings.ToLower(email), Name: "Demo Admin", Role: api.RoleAdmin, PasswordHash: h, CreatedAt: time.Now().UTC()})
			log.Info("seeded demo admin", "email", email)
		}
	}

	srv := &api.Server{
		Store: st, Hasher: hasher, Log: log,
		Tokens:         auth.Tokens{Secret: []byte(secret), TTL: 15 * time.Minute},
		AllowedOrigins: strings.Split(env("CORS_ORIGINS", "http://localhost:5173,http://localhost:4200"), ","),
	}
	hs := &http.Server{
		Addr: env("ADDR", ":8080"), Handler: srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Info("listening", "addr", hs.Addr)
		if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
}
