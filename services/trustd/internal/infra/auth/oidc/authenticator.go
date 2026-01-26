package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
)

const (
	defaultHTTPTimeout = 5 * time.Second
	discoveryPath      = "/.well-known/openid-configuration"
)

type Authenticator struct {
	issuer    string
	audience  string
	jwksURL   string
	clockSkew time.Duration
	jwks      *jwksCache
}

type Option func(*Authenticator)

func WithHTTPClient(client *http.Client) Option {
	return func(a *Authenticator) {
		if client != nil {
			a.jwks.httpClient = client
		}
	}
}

func NewAuthenticator(cfg config.Config, opts ...Option) (*Authenticator, error) {
	issuer := strings.TrimSpace(cfg.OIDCIssuerURL)
	if issuer == "" {
		return nil, errors.New("OIDC_ISSUER_URL is required")
	}
	jwksURL := strings.TrimSpace(cfg.OIDCJWKSURL)
	client := &http.Client{Timeout: defaultHTTPTimeout}
	if jwksURL == "" {
		discovered, err := discoverJWKSURL(context.Background(), client, issuer)
		if err != nil {
			return nil, err
		}
		jwksURL = discovered
	}
	auth := &Authenticator{
		issuer:    issuer,
		audience:  strings.TrimSpace(cfg.OIDCAudience),
		jwksURL:   jwksURL,
		clockSkew: time.Duration(cfg.OIDCClockSkewSecs) * time.Second,
		jwks:      newJWKSCache(jwksURL, client),
	}
	for _, opt := range opts {
		opt(auth)
	}
	return auth, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, bearerToken string) (domain.Principal, error) {
	if a == nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	tokenString := strings.TrimSpace(bearerToken)
	if tokenString == "" {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	header, claims, signingInput, signature, err := parseJWT(tokenString)
	if err != nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	if typ, ok := header["typ"].(string); ok {
		if typ != "" && strings.ToUpper(typ) != "JWT" {
			return domain.Principal{}, domain.ErrUnauthorized
		}
	}
	kid, _ := header["kid"].(string)
	pubKey, err := a.jwks.getKey(ctx, kid)
	if err != nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	if err := verifyRS256(pubKey, signingInput, signature); err != nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	if err := a.validateClaims(claims); err != nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	return principalFromClaims(claims), nil
}

func discoverJWKSURL(ctx context.Context, client *http.Client, issuer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+discoveryPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("oidc discovery failed")
	}
	var payload struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.JWKSURI == "" {
		return "", errors.New("oidc discovery missing jwks_uri")
	}
	return payload.JWKSURI, nil
}

func principalFromClaims(claims map[string]any) domain.Principal {
	principal := domain.Principal{
		RawClaims: claims,
	}
	if subject, _ := claims["sub"].(string); subject != "" {
		principal.Subject = subject
	}
	if tenantID, _ := claims["tenant_id"].(string); tenantID != "" {
		principal.TenantID = tenantID
	}
	if tenantID, _ := claims["tenant"].(string); principal.TenantID == "" && tenantID != "" {
		principal.TenantID = tenantID
	}
	principal.Roles = extractRoles(claims)
	principal.Scopes = extractScopes(claims)
	return principal
}

func extractRoles(claims map[string]any) []string {
	var roles []string
	if realmAccess, ok := claims["realm_access"].(map[string]any); ok {
		if rawRoles, ok := realmAccess["roles"].([]any); ok {
			for _, raw := range rawRoles {
				if role, ok := raw.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}
	if resourceAccess, ok := claims["resource_access"].(map[string]any); ok {
		for _, rawClient := range resourceAccess {
			client, ok := rawClient.(map[string]any)
			if !ok {
				continue
			}
			if rawRoles, ok := client["roles"].([]any); ok {
				for _, raw := range rawRoles {
					if role, ok := raw.(string); ok {
						roles = append(roles, role)
					}
				}
			}
		}
	}
	return dedupeStrings(roles)
}

func extractScopes(claims map[string]any) []string {
	var scopes []string
	if scope, ok := claims["scope"].(string); ok && scope != "" {
		scopes = append(scopes, strings.Fields(scope)...)
	}
	if raw, ok := claims["scp"].([]any); ok {
		for _, entry := range raw {
			if scope, ok := entry.(string); ok {
				scopes = append(scopes, scope)
			}
		}
	}
	return dedupeStrings(scopes)
}

func parseJWT(token string) (map[string]any, map[string]any, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("invalid token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, err
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, "", nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, "", nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	return header, claims, signingInput, signature, nil
}

func verifyRS256(pubKey *rsa.PublicKey, signingInput string, signature []byte) error {
	hash := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

func (a *Authenticator) validateClaims(claims map[string]any) error {
	now := time.Now()
	if a.issuer != "" {
		if iss, _ := claims["iss"].(string); iss != a.issuer {
			return errors.New("issuer mismatch")
		}
	}
	if a.audience != "" {
		if !audienceMatches(claims["aud"], a.audience) {
			return errors.New("audience mismatch")
		}
	}
	exp, ok := parseNumericDate(claims["exp"])
	if !ok {
		return errors.New("exp claim required")
	}
	if now.After(exp.Add(a.clockSkew)) {
		return errors.New("token expired")
	}
	if nbf, ok := parseNumericDate(claims["nbf"]); ok {
		if now.Add(a.clockSkew).Before(nbf) {
			return errors.New("token not yet valid")
		}
	}
	return nil
}

func parseNumericDate(value any) (time.Time, bool) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0), true
	default:
		return time.Time{}, false
	}
}

func audienceMatches(raw any, expected string) bool {
	switch v := raw.(type) {
	case string:
		return v == expected
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
