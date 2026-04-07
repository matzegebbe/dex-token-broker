package tokenbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	DexTokenURL          string
	HTTPTimeout          time.Duration
	CacheCleanupInterval time.Duration
	ExpirySafetyMargin   time.Duration
	AllowInsecureDexURL  bool
	UpstreamAuthHeader   string
	ClientIDHeader       string
	ClientSecretHeader   string
	ScopeHeader          string
	CacheMaxEntries      int
	StaticClientID       string
	StaticClientSecret   string
	StaticScope          string
	JWKSURL              string
	JWTHeader            string
	JWTIssuer            string
	JWTAudience          string
	UpstreamTokenHeaders string
}

type tokenHeaderMapping struct {
	jsonField  string
	headerName string
}

type Service struct {
	cache                *tokenCache
	flights              *flightGroup
	logger               *slog.Logger
	httpClient           *http.Client
	dexTokenURL          string
	upstreamAuthHeader   string
	clientIDHeader       string
	clientSecretHeader   string
	scopeHeader          string
	staticClientID       string
	staticClientSecret   string
	staticScope          string
	jwks                 *jwksValidator
	jwtHeader            string
	tokenHeaderMappings  []tokenHeaderMapping
	cacheCleanupInterval time.Duration
	expirySafetyMargin   time.Duration
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type cachedToken struct {
	Token        string
	ExpiresAt    time.Time
	ExtraHeaders map[string]string
}

const (
	maxClientIDLength     = 256
	maxClientSecretLength = 4096
	maxScopeLength        = 1024
	maxTokenResponseSize  = 64 * 1024
)

func New(cfg Config, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	cleanupInterval := cfg.CacheCleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	expiryMargin := cfg.ExpirySafetyMargin
	if expiryMargin <= 0 {
		expiryMargin = 30 * time.Second
	}

	dexTokenURL, err := validateDexTokenURL(cfg.DexTokenURL, cfg.AllowInsecureDexURL)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = timeout
	transport.ExpectContinueTimeout = time.Second
	transport.MaxIdleConns = 16
	transport.MaxIdleConnsPerHost = 8
	transport.MaxConnsPerHost = 32

	upstreamAuthHeader, err := normalizeHeaderName(cfg.UpstreamAuthHeader, "Authorization")
	if err != nil {
		return nil, fmt.Errorf("invalid upstream auth header: %w", err)
	}

	clientIDHeader, err := normalizeHeaderName(cfg.ClientIDHeader, "x-client-id")
	if err != nil {
		return nil, fmt.Errorf("invalid client id header: %w", err)
	}

	clientSecretHeader, err := normalizeHeaderName(cfg.ClientSecretHeader, "x-client-secret")
	if err != nil {
		return nil, fmt.Errorf("invalid client secret header: %w", err)
	}

	scopeHeader, err := normalizeHeaderName(cfg.ScopeHeader, "x-scope")
	if err != nil {
		return nil, fmt.Errorf("invalid scope header: %w", err)
	}

	if cfg.CacheMaxEntries < 0 {
		return nil, errors.New("cache max entries must be greater than or equal to zero")
	}

	staticEnabled := cfg.StaticClientID != "" || cfg.StaticClientSecret != "" || cfg.StaticScope != ""
	if staticEnabled {
		if cfg.StaticClientID == "" || cfg.StaticClientSecret == "" {
			return nil, errors.New("STATIC_CLIENT_ID and STATIC_CLIENT_SECRET must both be set when static credentials are enabled")
		}
		if err := validateInboundHeaders(cfg.StaticClientID, cfg.StaticClientSecret, cfg.StaticScope, clientIDHeader, clientSecretHeader, scopeHeader); err != nil {
			return nil, fmt.Errorf("invalid static credentials: %w", err)
		}
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var jwksVal *jwksValidator
	var jwtHeaderName string
	if cfg.JWKSURL != "" {
		if cfg.StaticClientID == "" || cfg.StaticClientSecret == "" {
			return nil, errors.New("STATIC_CLIENT_ID and STATIC_CLIENT_SECRET must be set when JWKS_URL is configured")
		}

		parsed, err := url.Parse(cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("invalid JWKS URL: %w", err)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return nil, fmt.Errorf("JWKS URL scheme must be http or https: %q", parsed.Scheme)
		}
		if parsed.Scheme != "https" && !cfg.AllowInsecureDexURL {
			return nil, errors.New("JWKS URL must use https unless ALLOW_INSECURE_DEX_URL=true")
		}
		if parsed.Host == "" {
			return nil, errors.New("JWKS URL host must not be empty")
		}

		jwtHeaderName, err = normalizeHeaderName(cfg.JWTHeader, "Authorization")
		if err != nil {
			return nil, fmt.Errorf("invalid JWT header: %w", err)
		}

		jwksVal = newJWKSValidator(parsed.String(), cfg.JWTIssuer, cfg.JWTAudience, httpClient, logger)
	}

	var tokenHeaderMappings []tokenHeaderMapping
	if cfg.UpstreamTokenHeaders != "" {
		tokenHeaderMappings, err = parseTokenHeaderMappings(cfg.UpstreamTokenHeaders)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream token headers: %w", err)
		}
	}

	return &Service{
		cache:                newTokenCache(cfg.CacheMaxEntries),
		flights:              newFlightGroup(),
		logger:               logger,
		httpClient:           httpClient,
		dexTokenURL:          dexTokenURL,
		upstreamAuthHeader:   upstreamAuthHeader,
		clientIDHeader:       clientIDHeader,
		clientSecretHeader:   clientSecretHeader,
		scopeHeader:          scopeHeader,
		staticClientID:       cfg.StaticClientID,
		staticClientSecret:   cfg.StaticClientSecret,
		staticScope:          cfg.StaticScope,
		jwks:                 jwksVal,
		jwtHeader:            jwtHeaderName,
		tokenHeaderMappings:  tokenHeaderMappings,
		cacheCleanupInterval: cleanupInterval,
		expirySafetyMargin:   expiryMargin,
	}, nil
}

func (s *Service) StartJanitor(ctx context.Context) {
	s.cache.StartJanitor(ctx, s.cacheCleanupInterval, s.logger)
}

func (s *Service) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	setCommonResponseHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Service) CheckHandler(w http.ResponseWriter, r *http.Request) {
	setCommonResponseHeaders(w)
	defer r.Body.Close()

	s.logger.Debug("incoming request", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.logger.Debug("rejecting request", "reason", "method not allowed", "method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.jwks != nil {
		if err := s.validateIncomingJWT(r); err != nil {
			s.logger.Warn("JWT validation failed", "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.logger.Debug("JWT validation passed")
	}

	clientID, clientSecret, scope := s.credentialsForRequest(r)

	s.logger.Debug("resolved credentials", "client_id", clientID, "scope", scope, "static", s.staticClientID != "")

	if err := validateInboundHeaders(clientID, clientSecret, scope, s.clientIDHeader, s.clientSecretHeader, s.scopeHeader); err != nil {
		var requestErr *tokenRequestError
		if errors.As(err, &requestErr) {
			s.logger.Debug("request validation failed", "status_code", requestErr.StatusCode, "message", requestErr.Message)
			http.Error(w, requestErr.Message, requestErr.StatusCode)
			return
		}
		s.logger.Debug("request validation failed", "error", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cacheKey := buildCacheKey(clientID, clientSecret, scope)

	if entry, ok := s.cache.Get(cacheKey); ok {
		s.logger.Debug("cache hit", "client_id", clientID, "scope", scope)
		s.writeAuthorized(w, entry)
		return
	}

	s.logger.Debug("cache miss, requesting token", "client_id", clientID, "scope", scope)

	result, err := s.flights.Do(cacheKey, func() (cachedToken, error) {
		if entry, ok := s.cache.Get(cacheKey); ok {
			return entry, nil
		}

		response, extraHeaders, err := s.requestToken(r.Context(), clientID, clientSecret, scope)
		if err != nil {
			return cachedToken{}, err
		}

		entry := cachedToken{
			Token:        response.AccessToken,
			ExpiresAt:    s.computeExpiry(response.ExpiresIn),
			ExtraHeaders: extraHeaders,
		}
		s.cache.Set(cacheKey, entry.Token, entry.ExpiresAt, extraHeaders)

		return entry, nil
	})
	if err != nil {
		var requestErr *tokenRequestError
		if errors.As(err, &requestErr) {
			s.logger.Warn(
				"token request failed",
				"client_id", clientID,
				"scope", scope,
				"status_code", requestErr.StatusCode,
				"error", requestErr.Cause,
			)
			http.Error(w, requestErr.Message, requestErr.StatusCode)
			return
		}

		s.logger.Error("unexpected token error", "client_id", clientID, "scope", scope, "error", err)
		http.Error(w, "token request failed", http.StatusUnauthorized)
		return
	}

	s.writeAuthorized(w, result)
}

func (s *Service) writeAuthorized(w http.ResponseWriter, entry cachedToken) {
	setCommonResponseHeaders(w)
	w.Header().Set(s.upstreamAuthHeader, "Bearer "+entry.Token)
	for name, value := range entry.ExtraHeaders {
		w.Header().Set(name, value)
	}
	w.WriteHeader(http.StatusOK)
	s.logger.Debug("authorized response sent", "auth_header", s.upstreamAuthHeader, "extra_headers", len(entry.ExtraHeaders))
}

func (s *Service) credentialsForRequest(r *http.Request) (clientID, clientSecret, scope string) {
	if s.staticClientID != "" || s.staticClientSecret != "" {
		return s.staticClientID, s.staticClientSecret, s.staticScope
	}

	return strings.TrimSpace(r.Header.Get(s.clientIDHeader)), r.Header.Get(s.clientSecretHeader), strings.TrimSpace(r.Header.Get(s.scopeHeader))
}

func (s *Service) validateIncomingJWT(r *http.Request) error {
	headerValue := r.Header.Get(s.jwtHeader)
	if headerValue == "" {
		return errors.New("missing JWT")
	}

	token := extractBearerToken(headerValue)
	if token == "" {
		return errors.New("empty bearer token")
	}

	return s.jwks.ValidateToken(r.Context(), token)
}

func (s *Service) requestToken(ctx context.Context, clientID, clientSecret, scope string) (oauthTokenResponse, map[string]string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.dexTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to build token request",
			Cause:      err,
		}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	s.logger.Debug("outgoing token request", "method", http.MethodPost, "url", s.dexTokenURL, "client_id", clientID, "scope", scope)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Debug("token request failed", "error", err)
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusServiceUnavailable,
			Message:    "oauth provider unavailable",
			Cause:      err,
		}
	}
	defer resp.Body.Close()

	s.logger.Debug("token response received", "status", resp.StatusCode, "content_length", resp.ContentLength)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize+1))
	if err != nil {
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusBadGateway,
			Message:    "failed to read token response",
			Cause:      err,
		}
	}

	if len(body) > maxTokenResponseSize {
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusBadGateway,
			Message:    "token response too large",
			Cause:      errors.New("oauth response exceeded size limit"),
		}
	}

	if resp.StatusCode != http.StatusOK {
		s.logger.Debug("token request upstream error", "status", resp.StatusCode, "body", truncateBody(body))
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: mapUpstreamStatus(resp.StatusCode),
			Message:    "token request failed",
			Cause:      fmt.Errorf("oauth provider returned %s: %s", resp.Status, truncateBody(body)),
		}
	}

	var token oauthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusBadGateway,
			Message:    "invalid token response",
			Cause:      err,
		}
	}

	if err := validateTokenResponse(token); err != nil {
		return oauthTokenResponse{}, nil, &tokenRequestError{
			StatusCode: http.StatusBadGateway,
			Message:    "invalid token response",
			Cause:      err,
		}
	}

	s.logger.Debug("token acquired", "token_type", token.TokenType, "expires_in", token.ExpiresIn)

	return token, s.extractTokenHeaders(body), nil
}

func (s *Service) computeExpiry(expiresIn int) time.Time {
	now := time.Now()

	if expiresIn <= 0 {
		return now.Add(60 * time.Second)
	}

	lifetime := time.Duration(expiresIn) * time.Second
	margin := s.expirySafetyMargin
	if lifetime <= margin {
		margin = lifetime / 5
		if margin <= 0 {
			margin = time.Second
		}
	}

	return now.Add(lifetime - margin)
}

func validateDexTokenURL(rawURL string, allowInsecure bool) (string, error) {
	if rawURL == "" {
		return "", errors.New("dex token url must not be empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse dex token url: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("dex token url scheme must be http or https: %q", parsed.Scheme)
	}

	if parsed.Scheme != "https" && !allowInsecure {
		return "", errors.New("dex token url must use https unless ALLOW_INSECURE_DEX_URL=true")
	}

	if parsed.Host == "" {
		return "", errors.New("dex token url host must not be empty")
	}

	return parsed.String(), nil
}

func validateInboundHeaders(clientID, clientSecret, scope, clientIDHeader, clientSecretHeader, scopeHeader string) error {
	if clientID == "" || clientSecret == "" {
		return &tokenRequestError{
			StatusCode: http.StatusUnauthorized,
			Message:    "missing credentials",
		}
	}

	if len(clientID) > maxClientIDLength {
		return &tokenRequestError{
			StatusCode: http.StatusBadRequest,
			Message:    clientIDHeader + " too long",
		}
	}

	if len(clientSecret) > maxClientSecretLength {
		return &tokenRequestError{
			StatusCode: http.StatusBadRequest,
			Message:    clientSecretHeader + " too long",
		}
	}

	if len(scope) > maxScopeLength {
		return &tokenRequestError{
			StatusCode: http.StatusBadRequest,
			Message:    scopeHeader + " too long",
		}
	}

	if hasInvalidHeaderValue(clientID) || hasInvalidHeaderValue(clientSecret) || hasInvalidHeaderValue(scope) {
		return &tokenRequestError{
			StatusCode: http.StatusBadRequest,
			Message:    "header contains invalid characters",
		}
	}

	return nil
}

func normalizeHeaderName(value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}

	if !isValidHeaderName(value) {
		return "", fmt.Errorf("invalid header name %q", value)
	}

	return textproto.CanonicalMIMEHeaderKey(value), nil
}

func validateTokenResponse(token oauthTokenResponse) error {
	if token.AccessToken == "" {
		return errors.New("empty access_token")
	}

	if hasInvalidHeaderValue(token.AccessToken) {
		return errors.New("access_token contains invalid header characters")
	}

	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer") {
		return fmt.Errorf("unsupported token_type %q", token.TokenType)
	}

	return nil
}

func (s *Service) extractTokenHeaders(body []byte) map[string]string {
	if len(s.tokenHeaderMappings) == 0 {
		return nil
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	headers := make(map[string]string, len(s.tokenHeaderMappings))
	for _, m := range s.tokenHeaderMappings {
		val, ok := raw[m.jsonField]
		if !ok {
			continue
		}

		strVal := formatJSONValue(val)
		if strVal != "" && !hasInvalidHeaderValue(strVal) {
			headers[m.headerName] = strVal
		}
	}
	return headers
}

func formatJSONValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	default:
		return ""
	}
}

func parseTokenHeaderMappings(raw string) ([]tokenHeaderMapping, error) {
	var mappings []tokenHeaderMapping

	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		jsonField, headerName, hasSep := strings.Cut(part, ":")
		jsonField = strings.TrimSpace(jsonField)
		if !hasSep {
			headerName = jsonField
		} else {
			headerName = strings.TrimSpace(headerName)
		}

		if jsonField == "" {
			return nil, errors.New("empty field name in token header mapping")
		}

		normalized, err := normalizeHeaderName(headerName, headerName)
		if err != nil {
			return nil, fmt.Errorf("invalid header name %q in token header mapping: %w", headerName, err)
		}

		mappings = append(mappings, tokenHeaderMapping{
			jsonField:  jsonField,
			headerName: normalized,
		})
	}

	return mappings, nil
}

func buildCacheKey(clientID, clientSecret, scope string) string {
	sum := sha256.Sum256([]byte(clientSecret))
	return strings.Join([]string{
		clientID,
		scope,
		hex.EncodeToString(sum[:]),
	}, "|")
}

func mapUpstreamStatus(statusCode int) int {
	switch {
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden || statusCode == http.StatusBadRequest:
		return http.StatusUnauthorized
	case statusCode >= 500:
		return http.StatusBadGateway
	default:
		return http.StatusUnauthorized
	}
}

func truncateBody(body []byte) string {
	const limit = 256

	value := strings.TrimSpace(string(body))
	if len(value) <= limit {
		return value
	}

	return value[:limit] + "..."
}

func hasInvalidHeaderValue(value string) bool {
	for _, r := range value {
		if r == '\r' || r == '\n' {
			return true
		}

		if r < 0x20 || r == 0x7f {
			return true
		}
	}

	return false
}

func isValidHeaderName(value string) bool {
	if value == "" {
		return false
	}

	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}

		switch b {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}

	return true
}

func setCommonResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

type tokenRequestError struct {
	StatusCode int
	Message    string
	Cause      error
}

func (e *tokenRequestError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return e.Message
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Cause)
}

type tokenCache struct {
	mu         sync.RWMutex
	items      map[string]cachedToken
	maxEntries int
}

func newTokenCache(maxEntries int) *tokenCache {
	return &tokenCache{
		items:      make(map[string]cachedToken),
		maxEntries: maxEntries,
	}
}

func (c *tokenCache) Get(key string) (cachedToken, bool) {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return cachedToken{}, false
	}

	if now.After(entry.ExpiresAt) {
		c.mu.Lock()
		current, exists := c.items[key]
		if exists && now.After(current.ExpiresAt) {
			delete(c.items, key)
		}
		c.mu.Unlock()
		return cachedToken{}, false
	}

	return entry, true
}

func (c *tokenCache) Set(key, token string, expiresAt time.Time, extraHeaders map[string]string) {
	c.mu.Lock()
	if c.maxEntries == 0 {
		c.mu.Unlock()
		return
	}

	if _, exists := c.items[key]; !exists && len(c.items) >= c.maxEntries {
		c.cleanupExpiredLocked(time.Now())
		if len(c.items) >= c.maxEntries {
			c.evictSoonestExpiringLocked()
		}
	}
	c.items[key] = cachedToken{
		Token:        token,
		ExpiresAt:    expiresAt,
		ExtraHeaders: extraHeaders,
	}
	c.mu.Unlock()
}

func (c *tokenCache) CleanupExpired() (removed int, remaining int) {
	now := time.Now()

	c.mu.Lock()
	removed = c.cleanupExpiredLocked(now)
	remaining = len(c.items)
	c.mu.Unlock()

	return removed, remaining
}

func (c *tokenCache) cleanupExpiredLocked(now time.Time) (removed int) {
	for key, entry := range c.items {
		if now.After(entry.ExpiresAt) {
			delete(c.items, key)
			removed++
		}
	}

	return removed
}

func (c *tokenCache) evictSoonestExpiringLocked() {
	var (
		evictKey string
		evictSet bool
		evictAt  time.Time
	)

	for key, entry := range c.items {
		if !evictSet || entry.ExpiresAt.Before(evictAt) {
			evictKey = key
			evictAt = entry.ExpiresAt
			evictSet = true
		}
	}

	if evictSet {
		delete(c.items, evictKey)
	}
}

func (c *tokenCache) StartJanitor(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, remaining := c.CleanupExpired()
				if removed > 0 {
					logger.Info("cache cleanup completed", "removed", removed, "remaining", remaining)
				}
			}
		}
	}()
}

type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done   chan struct{}
	result cachedToken
	err    error
}

func newFlightGroup() *flightGroup {
	return &flightGroup{
		calls: make(map[string]*flightCall),
	}
}

func (g *flightGroup) Do(key string, fn func() (cachedToken, error)) (cachedToken, error) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		<-call.done
		return call.result, call.err
	}

	call := &flightCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	call.result, call.err = fn()
	close(call.done)

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()

	return call.result, call.err
}
