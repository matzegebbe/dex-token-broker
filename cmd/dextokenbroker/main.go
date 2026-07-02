package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/matzegebbe/DexTokenBroker/internal/tokenbroker"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service exited with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("DexTokenBroker %s (commit=%s built=%s)\n", version, commit, date)
		return nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	service, err := tokenbroker.New(cfg.Broker, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service.StartJanitor(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/check", service.CheckHandler)
	mux.HandleFunc("/check/", service.CheckHandler)
	mux.HandleFunc("/healthz", service.HealthHandler)

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 * 1024,
		ErrorLog:          log.New(slog.NewLogLogger(logger.Handler(), slog.LevelError).Writer(), "", 0),
	}

	errCh := make(chan error, 1)

	go func() {
		logger.Info(
			"starting DexTokenBroker",
			"listen_addr", cfg.ListenAddress,
			"dex_token_url", cfg.Broker.DexTokenURL,
			"version", version,
		)
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}

	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

type runtimeConfig struct {
	ListenAddress   string
	ShutdownTimeout time.Duration
	LogLevel        slog.Level
	Broker          tokenbroker.Config
}

func loadConfig() (runtimeConfig, error) {
	requestTimeout, err := durationFromEnv("HTTP_TIMEOUT", 5*time.Second)
	if err != nil {
		return runtimeConfig{}, err
	}

	cleanupInterval, err := durationFromEnv("CACHE_CLEANUP_INTERVAL", 5*time.Minute)
	if err != nil {
		return runtimeConfig{}, err
	}

	expiryMargin, err := durationFromEnv("EXPIRY_SAFETY_MARGIN", 30*time.Second)
	if err != nil {
		return runtimeConfig{}, err
	}

	shutdownTimeout, err := durationFromEnv("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return runtimeConfig{}, err
	}

	cacheMaxEntries, err := intFromEnv("CACHE_MAX_ENTRIES", 1024)
	if err != nil {
		return runtimeConfig{}, err
	}

	logLevel, err := logLevelFromEnv("LOG_LEVEL", slog.LevelInfo)
	if err != nil {
		return runtimeConfig{}, err
	}

	listenAddress := getenv("LISTEN_ADDR", ":8080")
	dexTokenURL := getenv("DEX_TOKEN_URL", "https://dex.dex.svc.cluster.local/token")
	upstreamAuthHeader := getenv("UPSTREAM_AUTH_HEADER", "Authorization")
	clientIDHeader := getenv("CLIENT_ID_HEADER", "x-client-id")
	clientSecretHeader := getenv("CLIENT_SECRET_HEADER", "x-client-secret")
	scopeHeader := getenv("SCOPE_HEADER", "x-scope")
	staticClientID := os.Getenv("STATIC_CLIENT_ID")
	staticClientSecret := os.Getenv("STATIC_CLIENT_SECRET")
	staticScope := os.Getenv("STATIC_SCOPE")
	jwksURL := os.Getenv("JWKS_URL")
	jwksURLs := splitAndTrim(os.Getenv("JWKS_URLS"))
	jwksProviders, err := parseJWKSProviders(os.Getenv("JWKS_PROVIDERS"))
	if err != nil {
		return runtimeConfig{}, err
	}
	jwtHeader := getenv("JWT_HEADER", "Authorization")
	jwtIssuer := os.Getenv("JWT_ISSUER")
	jwtAudience := os.Getenv("JWT_AUDIENCE")
	upstreamTokenHeaders := os.Getenv("UPSTREAM_TOKEN_HEADERS")
	allowInsecureDexURL, err := boolFromEnv("ALLOW_INSECURE_DEX_URL", false)
	if err != nil {
		return runtimeConfig{}, err
	}

	return runtimeConfig{
		ListenAddress:   listenAddress,
		ShutdownTimeout: shutdownTimeout,
		LogLevel:        logLevel,
		Broker: tokenbroker.Config{
			DexTokenURL:          dexTokenURL,
			HTTPTimeout:          requestTimeout,
			CacheCleanupInterval: cleanupInterval,
			ExpirySafetyMargin:   expiryMargin,
			AllowInsecureDexURL:  allowInsecureDexURL,
			UpstreamAuthHeader:   upstreamAuthHeader,
			ClientIDHeader:       clientIDHeader,
			ClientSecretHeader:   clientSecretHeader,
			ScopeHeader:          scopeHeader,
			CacheMaxEntries:      cacheMaxEntries,
			StaticClientID:       staticClientID,
			StaticClientSecret:   staticClientSecret,
			StaticScope:          staticScope,
			JWKSURL:              jwksURL,
			JWKSURLs:             jwksURLs,
			JWKSProviders:        jwksProviders,
			JWTHeader:            jwtHeader,
			JWTIssuer:            jwtIssuer,
			JWTAudience:          jwtAudience,
			UpstreamTokenHeaders: upstreamTokenHeaders,
		},
	}, nil
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}

	return parsed, nil
}

func boolFromEnv(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}

	return parsed, nil
}

func intFromEnv(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}

	return parsed, nil
}

func logLevelFromEnv(key string, fallback slog.Level) (slog.Level, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(value)); err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}

	return level, nil
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

// splitAndTrim parses a comma-separated environment value into a trimmed,
// non-empty list. An empty value yields a nil slice.
func splitAndTrim(value string) []string {
	if value == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

// stringOrSlice accepts a JSON value that is either a single string or an array
// of strings, normalizing both into a trimmed, non-empty slice.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single = strings.TrimSpace(single); single != "" {
			*s = stringOrSlice{single}
		}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return errors.New("expected a string or array of strings")
	}

	var out []string
	for _, v := range multi {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	*s = out
	return nil
}

// parseJWKSProviders decodes the JWKS_PROVIDERS JSON array into provider
// definitions with per-provider issuer and audience allowlists.
func parseJWKSProviders(raw string) ([]tokenbroker.JWKSProvider, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var entries []struct {
		URL      string        `json:"url"`
		Issuer   stringOrSlice `json:"issuer"`
		Audience stringOrSlice `json:"audience"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("parse JWKS_PROVIDERS: %w", err)
	}

	providers := make([]tokenbroker.JWKSProvider, 0, len(entries))
	for i, e := range entries {
		if strings.TrimSpace(e.URL) == "" {
			return nil, fmt.Errorf("parse JWKS_PROVIDERS: entry %d is missing a url", i)
		}
		providers = append(providers, tokenbroker.JWKSProvider{
			URL:       strings.TrimSpace(e.URL),
			Issuers:   []string(e.Issuer),
			Audiences: []string(e.Audience),
		})
	}

	return providers, nil
}
