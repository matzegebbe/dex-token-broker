package main

import "testing"

func TestParseJWKSProviders(t *testing.T) {
	t.Run("empty input yields nil", func(t *testing.T) {
		providers, err := parseJWKSProviders("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if providers != nil {
			t.Fatalf("expected nil providers, got %v", providers)
		}
	})

	t.Run("string and array audiences", func(t *testing.T) {
		raw := `[
			{"url":"https://a.example/jwks","issuer":"https://a.example/","audience":"api-a"},
			{"url":"https://b.example/jwks","audience":["api-b","api-b2"]}
		]`
		providers, err := parseJWKSProviders(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(providers) != 2 {
			t.Fatalf("expected 2 providers, got %d", len(providers))
		}
		if providers[0].URL != "https://a.example/jwks" {
			t.Fatalf("unexpected url: %q", providers[0].URL)
		}
		if len(providers[0].Issuers) != 1 || providers[0].Issuers[0] != "https://a.example/" {
			t.Fatalf("unexpected issuers: %v", providers[0].Issuers)
		}
		if len(providers[0].Audiences) != 1 || providers[0].Audiences[0] != "api-a" {
			t.Fatalf("unexpected audiences: %v", providers[0].Audiences)
		}
		if len(providers[1].Audiences) != 2 {
			t.Fatalf("expected 2 audiences for array form, got %v", providers[1].Audiences)
		}
		if len(providers[1].Issuers) != 0 {
			t.Fatalf("expected no issuers when omitted, got %v", providers[1].Issuers)
		}
	})

	t.Run("missing url is rejected", func(t *testing.T) {
		_, err := parseJWKSProviders(`[{"audience":"api-a"}]`)
		if err == nil {
			t.Fatal("expected error for entry without url")
		}
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		_, err := parseJWKSProviders(`{not json`)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}
