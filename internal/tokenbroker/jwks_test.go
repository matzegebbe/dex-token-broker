package tokenbroker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJWKSValidateValidToken(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "test-subject",
	})

	if err := validator.ValidateToken(context.Background(), token); err != nil {
		t.Fatalf("expected valid token: %v", err)
	}
}

func TestJWKSRejectExpiredToken(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	if err := validator.ValidateToken(context.Background(), token); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestJWKSRejectMissingExpClaim(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"sub": "test-subject",
	})

	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected token without exp to be rejected")
	}
	if !strings.Contains(err.Error(), "exp") {
		t.Fatalf("expected exp-related error, got: %v", err)
	}
}

func TestJWKSRejectNotYetValidToken(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(time.Hour).Unix(),
	})

	if err := validator.ValidateToken(context.Background(), token); err == nil {
		t.Fatal("expected not-yet-valid token to be rejected")
	}
}

func TestJWKSRejectInvalidSignature(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	otherKey := generateRSAKey(t)

	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, otherKey, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	if err := validator.ValidateToken(context.Background(), token); err == nil {
		t.Fatal("expected invalid signature to be rejected")
	}
}

func TestJWKSRejectAlgNone(t *testing.T) {
	t.Parallel()

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":9999999999}`))
	token := header + "." + payload + "."

	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected alg=none to be rejected")
	}
	if !strings.Contains(err.Error(), "disallowed") {
		t.Fatalf("expected algorithm disallowed error, got: %v", err)
	}
}

func TestJWKSRejectHMACAlgorithm(t *testing.T) {
	t.Parallel()

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	token := header + "." + payload + "." + sig

	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected HS256 to be rejected")
	}
	if !strings.Contains(err.Error(), "disallowed") {
		t.Fatalf("expected algorithm disallowed error, got: %v", err)
	}
}

func TestJWKSRejectAlgorithmKeyMismatch(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)

	set := jwksSet{
		Keys: []jwkKey{{
			Kty: "RSA",
			Kid: "kid-1",
			Use: "sig",
			Alg: "RS512",
			N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected algorithm mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match key algorithm") {
		t.Fatalf("expected algorithm mismatch error, got: %v", err)
	}
}

func TestJWKSRejectEmptySignature(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "")

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"kid-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":9999999999}`))
	token := header + "." + payload + "."

	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected empty signature to be rejected")
	}
	if !strings.Contains(err.Error(), "empty signature") {
		t.Fatalf("expected empty signature error, got: %v", err)
	}
}

func TestJWKSRejectOversizedToken(t *testing.T) {
	t.Parallel()

	validator := newTestValidator("https://unused.example", "", "")

	token := strings.Repeat("a", maxJWTSize+1)
	err := validator.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected oversized token to be rejected")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("expected size error, got: %v", err)
	}
}

func TestJWKSValidateIssuer(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "https://auth.example.com", "")

	t.Run("matching issuer passes", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": "https://auth.example.com",
		})
		if err := validator.ValidateToken(context.Background(), token); err != nil {
			t.Fatalf("expected valid token: %v", err)
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": "https://evil.example.com",
		})
		err := validator.ValidateToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected wrong issuer to be rejected")
		}
		if !strings.Contains(err.Error(), "issuer") {
			t.Fatalf("expected issuer error, got: %v", err)
		}
	})

	t.Run("missing issuer rejected", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		err := validator.ValidateToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected missing issuer to be rejected")
		}
	})
}

func TestJWKSValidateAudience(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	validator := newTestValidator(jwksServer.URL, "", "my-service")

	t.Run("matching audience string passes", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": "my-service",
		})
		if err := validator.ValidateToken(context.Background(), token); err != nil {
			t.Fatalf("expected valid token: %v", err)
		}
	})

	t.Run("matching audience array passes", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": []string{"other-service", "my-service"},
		})
		if err := validator.ValidateToken(context.Background(), token); err != nil {
			t.Fatalf("expected valid token: %v", err)
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": "other-service",
		})
		err := validator.ValidateToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected wrong audience to be rejected")
		}
		if !strings.Contains(err.Error(), "audience") {
			t.Fatalf("expected audience error, got: %v", err)
		}
	})

	t.Run("missing audience rejected", func(t *testing.T) {
		token := signTestJWT(t, key, "kid-1", map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		err := validator.ValidateToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected missing audience to be rejected")
		}
	})
}

func TestJWKSRejectSmallRSAKey(t *testing.T) {
	t.Parallel()

	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small RSA key: %v", err)
	}

	jwk := jwkKey{
		Kty: "RSA",
		Kid: "small-key",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(smallKey.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(smallKey.PublicKey.E)).Bytes()),
	}

	_, err = parseJWK(jwk)
	if err == nil {
		t.Fatal("expected small RSA key to be rejected")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Fatalf("expected key size error, got: %v", err)
	}
}

func TestCheckHandlerWithJWKSValidJWT(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		StaticClientID:      "static-client",
		StaticClientSecret:  "static-secret",
		JWKSURL:             jwksServer.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{"access_token":"dex-token-123","token_type":"Bearer","expires_in":3600}`)
			return rec.Result(), nil
		}),
	}

	jwt := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "test-subject",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	service.CheckHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Authorization"); got != "Bearer dex-token-123" {
		t.Fatalf("expected upstream auth header, got %q", got)
	}
}

func TestCheckHandlerWithJWKSInvalidJWT(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		StaticClientID:      "static-client",
		StaticClientSecret:  "static-secret",
		JWKSURL:             jwksServer.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	service.CheckHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestCheckHandlerWithJWKSMissingJWT(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		StaticClientID:      "static-client",
		StaticClientSecret:  "static-secret",
		JWKSURL:             jwksServer.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)

	service.CheckHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestCheckHandlerWithJWKSCustomHeader(t *testing.T) {
	t.Parallel()

	key := generateRSAKey(t)
	jwksServer := newJWKSServer(t, &key.PublicKey, "kid-1")
	defer jwksServer.Close()

	service, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: true,
		StaticClientID:      "static-client",
		StaticClientSecret:  "static-secret",
		JWKSURL:             jwksServer.URL,
		JWTHeader:           "X-Auth-Token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{"access_token":"dex-token-456","token_type":"Bearer","expires_in":3600}`)
			return rec.Result(), nil
		}),
	}

	jwt := signTestJWT(t, key, "kid-1", map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("X-Auth-Token", "Bearer "+jwt)

	service.CheckHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNewRejectsJWKSWithoutStaticCredentials(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		DexTokenURL: "https://dex.example/token",
		JWKSURL:     "https://auth.example/.well-known/jwks.json",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected JWKS without static credentials to be rejected")
	}
}

func TestNewRejectsInsecureJWKSURL(t *testing.T) {
	t.Parallel()

	_, err := New(Config{
		DexTokenURL:         "http://dex.example/token",
		AllowInsecureDexURL: false,
		JWKSURL:             "http://auth.example/.well-known/jwks.json",
		StaticClientID:      "client",
		StaticClientSecret:  "secret",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected insecure JWKS URL to be rejected")
	}
}

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"Bearer eyJhbGci", "eyJhbGci"},
		{"bearer eyJhbGci", "eyJhbGci"},
		{"BEARER eyJhbGci", "eyJhbGci"},
		{"eyJhbGci", "eyJhbGci"},
		{"", ""},
		{"Bearer ", ""},
	}

	for _, tt := range tests {
		if got := extractBearerToken(tt.input); got != tt.want {
			t.Errorf("extractBearerToken(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseTokenHeaderMappings(t *testing.T) {
	t.Parallel()

	t.Run("simple field name used as header name", func(t *testing.T) {
		mappings, err := parseTokenHeaderMappings("access_token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mappings) != 1 {
			t.Fatalf("expected 1 mapping, got %d", len(mappings))
		}
		if mappings[0].jsonField != "access_token" {
			t.Fatalf("expected field access_token, got %q", mappings[0].jsonField)
		}
		if mappings[0].headerName != "Access_token" {
			t.Fatalf("expected header Access_token (normalized), got %q", mappings[0].headerName)
		}
	})

	t.Run("explicit field:header mapping", func(t *testing.T) {
		mappings, err := parseTokenHeaderMappings("access_token:X-Access-Token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mappings) != 1 {
			t.Fatalf("expected 1 mapping, got %d", len(mappings))
		}
		if mappings[0].jsonField != "access_token" || mappings[0].headerName != "X-Access-Token" {
			t.Fatalf("unexpected mapping: %+v", mappings[0])
		}
	})

	t.Run("multiple mappings", func(t *testing.T) {
		mappings, err := parseTokenHeaderMappings("access_token, token_type:X-Token-Type")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mappings) != 2 {
			t.Fatalf("expected 2 mappings, got %d", len(mappings))
		}
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		mappings, err := parseTokenHeaderMappings("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mappings) != 0 {
			t.Fatalf("expected 0 mappings, got %d", len(mappings))
		}
	})

	t.Run("invalid header name rejected", func(t *testing.T) {
		_, err := parseTokenHeaderMappings("access_token:Bad Header")
		if err == nil {
			t.Fatal("expected invalid header name to be rejected")
		}
	})
}

func TestCheckHandlerWithTokenHeaderMapping(t *testing.T) {
	t.Parallel()

	service, err := New(Config{
		DexTokenURL:          "http://dex.example/token",
		AllowInsecureDexURL:  true,
		UpstreamTokenHeaders: "access_token,token_type:X-Token-Type",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}`)
			return rec.Result(), nil
		}),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/check", nil)
	req.Header.Set("x-client-id", "svc-a")
	req.Header.Set("x-client-secret", "secret-1")

	service.CheckHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Authorization"); got != "Bearer tok-abc" {
		t.Fatalf("expected Authorization header, got %q", got)
	}
	if got := rec.Header().Get("Access_token"); got != "tok-abc" {
		t.Fatalf("expected access_token header %q, got %q", "tok-abc", got)
	}
	if got := rec.Header().Get("X-Token-Type"); got != "Bearer" {
		t.Fatalf("expected X-Token-Type header %q, got %q", "Bearer", got)
	}
}

func TestTokenHeaderMappingCached(t *testing.T) {
	t.Parallel()

	var calls int
	service, err := New(Config{
		DexTokenURL:          "http://dex.example/token",
		AllowInsecureDexURL:  true,
		CacheMaxEntries:      1024,
		UpstreamTokenHeaders: "access_token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("expected broker to initialize: %v", err)
	}

	service.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{"access_token":"tok-cached","token_type":"Bearer","expires_in":3600}`)
			return rec.Result(), nil
		}),
	}

	makeRequest := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/check", nil)
		req.Header.Set("x-client-id", "svc-a")
		req.Header.Set("x-client-secret", "secret-1")
		service.CheckHandler(rec, req)
		return rec
	}

	first := makeRequest()
	if first.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", first.Code)
	}

	second := makeRequest()
	if second.Code != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", second.Code)
	}

	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}

	if got := second.Header().Get("Access_token"); got != "tok-cached" {
		t.Fatalf("expected cached access_token header, got %q", got)
	}
}

// Test helpers

func newTestValidator(jwksURL, issuer, audience string) *jwksValidator {
	return newJWKSValidator(jwksURL, issuer, audience, http.DefaultClient, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func newJWKSServer(t *testing.T, pub *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	set := jwksSet{
		Keys: []jwkKey{{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": kid,
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
