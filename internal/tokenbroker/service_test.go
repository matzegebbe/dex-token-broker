package tokenbroker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildCacheKeyUsesSecretFingerprint(t *testing.T) {
	t.Parallel()

	keyA := buildCacheKey("service-a", "secret-one", "api.read")
	keyB := buildCacheKey("service-a", "secret-two", "api.read")

	if keyA == keyB {
		t.Fatal("expected different cache keys for different secrets")
	}
}

func TestCheckHandlerCachesTokenPerCredentialSet(t *testing.T) {
	t.Parallel()

	var calls int
	service, err := New(Config{
		DexTokenURL:          "http://dex.example/token",
		HTTPTimeout:          2 * time.Second,
		CacheCleanupInterval: time.Minute,
		ExpirySafetyMargin:   30 * time.Second,
		AllowInsecureDexURL:  true,
		CacheMaxEntries:      1024,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			recorder.WriteHeader(http.StatusOK)
			_, _ = recorder.WriteString(`{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`)

			return recorder.Result(), nil
		}),
	}

	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		req.Header.Set("x-client-id", "service-a")
		req.Header.Set("x-client-secret", "secret-one")
		req.Header.Set("x-scope", "api.read")
		service.CheckHandler(recorder, req)
		return recorder
	}

	first := request()
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", first.Code)
	}

	second := request()
	if second.Code != http.StatusOK {
		t.Fatalf("expected second request to succeed, got %d", second.Code)
	}

	if calls != 1 {
		t.Fatalf("expected one upstream token request, got %d", calls)
	}

	if got := second.Header().Get("Authorization"); got != "Bearer token-123" {
		t.Fatalf("expected cached Authorization header, got %q", got)
	}
}

func TestCheckHandlerRejectsMissingCredentials(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL:         "https://dex.example/token",
		AllowInsecureDexURL: false,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestCacheCleanupExpiredRemovesEntries(t *testing.T) {
	t.Parallel()

	cache := newTokenCache(16)
	cache.Set("expired", "token-a", time.Now().Add(-time.Second), nil)
	cache.Set("valid", "token-b", time.Now().Add(time.Minute), nil)

	removed, remaining := cache.CleanupExpired()

	if removed != 1 {
		t.Fatalf("expected one removed entry, got %d", removed)
	}

	if remaining != 1 {
		t.Fatalf("expected one remaining entry, got %d", remaining)
	}
}

func TestStartJanitorStopsWithContext(t *testing.T) {
	t.Parallel()

	cache := newTokenCache(16)
	cache.Set("expired", "token-a", time.Now().Add(-time.Second), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cache.StartJanitor(ctx, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))

	time.Sleep(30 * time.Millisecond)
	cancel()

	if _, ok := cache.Get("expired"); ok {
		t.Fatal("expected expired token to be removed")
	}
}

func TestMapUpstreamStatus(t *testing.T) {
	t.Parallel()

	if got := mapUpstreamStatus(http.StatusUnauthorized); got != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized mapping, got %d", got)
	}

	if got := mapUpstreamStatus(http.StatusInternalServerError); got != http.StatusBadGateway {
		t.Fatalf("expected bad gateway mapping, got %d", got)
	}
}

func TestTruncateBody(t *testing.T) {
	t.Parallel()

	longBody := strings.Repeat("a", 300)
	truncated := truncateBody([]byte(longBody))
	if len(truncated) <= 256 {
		t.Fatalf("expected truncated body to exceed 256 with ellipsis, got %d", len(truncated))
	}
}

func TestNewRejectsInsecureDexURLByDefault(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		DexTokenURL: "http://dex.example/token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected insecure dex url to be rejected")
	}
}

func TestCheckHandlerRejectsMethod(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL: "https://dex.example/token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/check", nil)
	req.Header.Set("x-client-id", "service-a")
	req.Header.Set("x-client-secret", "secret-one")

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}
}

func TestCheckHandlerRejectsOversizedClientID(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL: "https://dex.example/token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/check", nil)
	req.Header.Set("x-client-id", strings.Repeat("a", maxClientIDLength+1))
	req.Header.Set("x-client-secret", "secret-one")

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestCheckHandlerRejectsInvalidTokenType(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			recorder.WriteHeader(http.StatusOK)
			_, _ = recorder.WriteString(`{"access_token":"token-123","token_type":"MAC","expires_in":3600}`)
			return recorder.Result(), nil
		}),
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/check", nil)
	req.Header.Set("x-client-id", "service-a")
	req.Header.Set("x-client-secret", "secret-one")

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
}

func TestCheckHandlerUsesStaticCredentials(t *testing.T) {
	t.Parallel()

	var authHeader string
	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		StaticClientID:      "static-client",
		StaticClientSecret:  "static-secret",
		StaticScope:         "broker.scope",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			authHeader = r.Header.Get("Authorization")
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			recorder.WriteHeader(http.StatusOK)
			_, _ = recorder.WriteString(`{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`)
			return recorder.Result(), nil
		}),
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/check", nil)
	req.Header.Set("x-client-id", "request-client")
	req.Header.Set("x-client-secret", "request-secret")
	req.Header.Set("x-scope", "request.scope")

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	if authHeader == "" {
		t.Fatal("expected upstream auth header to be set")
	}

	if got := recorder.Header().Get("Authorization"); got != "Bearer token-123" {
		t.Fatalf("expected Authorization header, got %q", got)
	}
}

func TestCheckHandlerUsesConfiguredHeaderNames(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		ClientIDHeader:      "X-Broker-Client-ID",
		ClientSecretHeader:  "X-Broker-Client-Secret",
		ScopeHeader:         "X-Broker-Scope",
		UpstreamAuthHeader:  "X-Backend-Authorization",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			recorder.WriteHeader(http.StatusOK)
			_, _ = recorder.WriteString(`{"access_token":"token-abc","token_type":"Bearer","expires_in":3600}`)
			return recorder.Result(), nil
		}),
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/check", nil)
	req.Header.Set("X-Broker-Client-ID", "service-a")
	req.Header.Set("X-Broker-Client-Secret", "secret-one")
	req.Header.Set("X-Broker-Scope", "api.read")

	service.CheckHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	if got := recorder.Header().Get("X-Backend-Authorization"); got != "Bearer token-abc" {
		t.Fatalf("expected configured upstream header, got %q", got)
	}
}

func TestNewRejectsPartialStaticCredentials(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		DexTokenURL:    "https://dex.example/token",
		StaticClientID: "static-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected partial static credentials to be rejected")
	}
}

func TestNewRejectsInvalidHeaderName(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		DexTokenURL:        "https://dex.example/token",
		UpstreamAuthHeader: "Bad Header",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected invalid header name to be rejected")
	}
}

func TestCacheEvictsSoonestExpiringEntryAtCapacity(t *testing.T) {
	t.Parallel()

	cache := newTokenCache(2)
	cache.Set("a", "token-a", time.Now().Add(1*time.Minute), nil)
	cache.Set("b", "token-b", time.Now().Add(2*time.Minute), nil)
	cache.Set("c", "token-c", time.Now().Add(3*time.Minute), nil)

	if _, ok := cache.Get("a"); ok {
		t.Fatal("expected soonest expiring entry to be evicted")
	}

	if _, ok := cache.Get("b"); !ok {
		t.Fatal("expected entry b to remain in cache")
	}

	if _, ok := cache.Get("c"); !ok {
		t.Fatal("expected entry c to remain in cache")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
