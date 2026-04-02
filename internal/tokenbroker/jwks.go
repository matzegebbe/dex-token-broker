package tokenbroker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	jwksMinRefreshInterval = 5 * time.Minute
	maxJWKSResponseSize    = 512 * 1024
	maxJWTSize             = 16 * 1024
	minRSAKeyBits          = 2048
)

var allowedJWTAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

type jwksSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type parsedKey struct {
	publicKey crypto.PublicKey
	alg       string
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Exp *float64    `json:"exp"`
	Nbf *float64    `json:"nbf"`
	Iss string      `json:"iss"`
	Aud jwtAudience `json:"aud"`
}

type jwtAudience []string

func (a *jwtAudience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = jwtAudience{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("aud must be a string or array of strings: %w", err)
	}
	*a = jwtAudience(multi)
	return nil
}

type jwksValidator struct {
	mu        sync.RWMutex
	keys      map[string]parsedKey
	jwksURL   string
	issuer    string
	audience  string
	client    *http.Client
	logger    *slog.Logger
	lastFetch time.Time
	refreshMu sync.Mutex
}

func newJWKSValidator(jwksURL, issuer, audience string, client *http.Client, logger *slog.Logger) *jwksValidator {
	return &jwksValidator{
		keys:     make(map[string]parsedKey),
		jwksURL:  jwksURL,
		issuer:   issuer,
		audience: audience,
		client:   client,
		logger:   logger,
	}
}

func (v *jwksValidator) ValidateToken(ctx context.Context, rawToken string) error {
	if len(rawToken) > maxJWTSize {
		return errors.New("JWT exceeds maximum size")
	}

	parts := strings.SplitN(rawToken, ".", 3)
	if len(parts) != 3 {
		return errors.New("invalid JWT format")
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("decode JWT header: %w", err)
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return fmt.Errorf("parse JWT header: %w", err)
	}

	if !allowedJWTAlgorithms[hdr.Alg] {
		return fmt.Errorf("unsupported or disallowed JWT algorithm %q", hdr.Alg)
	}

	key, err := v.getKey(ctx, hdr.Kid)
	if err != nil {
		return err
	}

	if key.alg != "" && key.alg != hdr.Alg {
		return fmt.Errorf("JWT algorithm %q does not match key algorithm %q", hdr.Alg, key.alg)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("decode JWT signature: %w", err)
	}

	if len(signature) == 0 {
		return errors.New("JWT has empty signature")
	}

	if err := verifySignature(hdr.Alg, key.publicKey, signingInput, signature); err != nil {
		return err
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("parse JWT claims: %w", err)
	}

	if claims.Exp == nil {
		return errors.New("JWT missing required exp claim")
	}

	now := time.Now()

	if now.After(time.Unix(int64(*claims.Exp), 0)) {
		return errors.New("JWT has expired")
	}

	if claims.Nbf != nil {
		if now.Before(time.Unix(int64(*claims.Nbf), 0)) {
			return errors.New("JWT is not yet valid")
		}
	}

	if v.issuer != "" && claims.Iss != v.issuer {
		return fmt.Errorf("JWT issuer %q does not match expected %q", claims.Iss, v.issuer)
	}

	if v.audience != "" {
		found := false
		for _, aud := range claims.Aud {
			if aud == v.audience {
				found = true
				break
			}
		}
		if !found {
			return errors.New("JWT audience does not contain expected value")
		}
	}

	return nil
}

func (v *jwksValidator) getKey(ctx context.Context, kid string) (parsedKey, error) {
	if key, ok := v.lookupKey(kid); ok {
		return key, nil
	}

	if err := v.refreshIfNeeded(ctx); err != nil {
		v.mu.RLock()
		empty := len(v.keys) == 0
		v.mu.RUnlock()
		if empty {
			return parsedKey{}, fmt.Errorf("fetch JWKS: %w", err)
		}
		v.logger.Warn("JWKS refresh failed, using cached keys", "error", err)
	}

	if key, ok := v.lookupKey(kid); ok {
		return key, nil
	}

	if kid == "" {
		return parsedKey{}, errors.New("JWT has no kid and no unique key in JWKS")
	}
	return parsedKey{}, fmt.Errorf("key %q not found in JWKS", kid)
}

func (v *jwksValidator) lookupKey(kid string) (parsedKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if kid != "" {
		key, ok := v.keys[kid]
		return key, ok
	}

	if len(v.keys) == 1 {
		for _, key := range v.keys {
			return key, true
		}
	}

	return parsedKey{}, false
}

func (v *jwksValidator) refreshIfNeeded(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	v.mu.RLock()
	canRefresh := v.lastFetch.IsZero() || time.Since(v.lastFetch) >= jwksMinRefreshInterval
	v.mu.RUnlock()

	if !canRefresh {
		return nil
	}

	err := v.refresh(ctx)
	if err != nil {
		v.mu.Lock()
		v.lastFetch = time.Now()
		v.mu.Unlock()
	}
	return err
}

func (v *jwksValidator) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseSize+1))
	if err != nil {
		return fmt.Errorf("read JWKS response: %w", err)
	}

	if len(body) > maxJWKSResponseSize {
		return errors.New("JWKS response too large")
	}

	var set jwksSet
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("parse JWKS response: %w", err)
	}

	keys := make(map[string]parsedKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}

		pub, err := parseJWK(jwk)
		if err != nil {
			v.logger.Debug("skipping JWK", "kid", jwk.Kid, "error", err)
			continue
		}

		keys[jwk.Kid] = parsedKey{publicKey: pub, alg: jwk.Alg}
	}

	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	v.logger.Info("JWKS keys refreshed", "keys", len(keys))
	return nil
}

func parseJWK(key jwkKey) (crypto.PublicKey, error) {
	switch key.Kty {
	case "RSA":
		return parseRSAJWK(key)
	case "EC":
		return parseECJWK(key)
	default:
		return nil, fmt.Errorf("unsupported key type %q", key.Kty)
	}
}

func parseRSAJWK(key jwkKey) (*rsa.PublicKey, error) {
	nb, err := base64URLDecode(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode RSA modulus: %w", err)
	}

	eb, err := base64URLDecode(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)

	if !e.IsInt64() {
		return nil, errors.New("RSA exponent too large")
	}

	if n.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d)", n.BitLen(), minRSAKeyBits)
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECJWK(key jwkKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", key.Crv)
	}

	xb, err := base64URLDecode(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode EC x: %w", err)
	}

	yb, err := base64URLDecode(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decode EC y: %w", err)
	}

	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("EC point is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func verifySignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	hashAlg, err := cryptoHashForAlg(alg)
	if err != nil {
		return err
	}

	h := hashAlg.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	switch alg {
	case "RS256", "RS384", "RS512":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected RSA public key for RS* algorithm")
		}
		return rsa.VerifyPKCS1v15(rsaKey, hashAlg, digest, signature)

	case "ES256", "ES384", "ES512":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("expected EC public key for ES* algorithm")
		}

		keySize := (ecKey.Params().BitSize + 7) / 8
		if len(signature) != 2*keySize {
			return fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(signature), 2*keySize)
		}

		r := new(big.Int).SetBytes(signature[:keySize])
		s := new(big.Int).SetBytes(signature[keySize:])

		if !ecdsa.Verify(ecKey, digest, r, s) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func cryptoHashForAlg(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "ES512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func extractBearerToken(headerValue string) string {
	const prefix = "bearer "
	if len(headerValue) >= len(prefix) && strings.EqualFold(headerValue[:len(prefix)], prefix) {
		return strings.TrimSpace(headerValue[len(prefix):])
	}
	return strings.TrimSpace(headerValue)
}
