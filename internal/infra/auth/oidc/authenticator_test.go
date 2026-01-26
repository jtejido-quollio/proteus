package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"proteus/internal/config"
)

func TestAuthenticate_ValidToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := "https://jwks.test/keys"
	jwks := buildJWKS(t, &privKey.PublicKey, "kid-1")
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == jwksURL {
				return jsonResponse(http.StatusOK, jwks), nil
			}
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}),
	}

	cfg := config.Config{
		OIDCIssuerURL:     "https://issuer.test",
		OIDCAudience:      "proteus-api",
		OIDCJWKSURL:       jwksURL,
		OIDCClockSkewSecs: 60,
	}
	auth, err := NewAuthenticator(cfg, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":       cfg.OIDCIssuerURL,
		"aud":       cfg.OIDCAudience,
		"sub":       "user-1",
		"tenant_id": "tenant-1",
		"scope":     "manifests:record logs:read",
		"exp":       now.Add(5 * time.Minute).Unix(),
		"nbf":       now.Add(-1 * time.Minute).Unix(),
	}
	token := signToken(t, privKey, "kid-1", claims)

	principal, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.Subject != "user-1" {
		t.Fatalf("unexpected subject: %s", principal.Subject)
	}
	if principal.TenantID != "tenant-1" {
		t.Fatalf("unexpected tenant: %s", principal.TenantID)
	}
	if len(principal.Scopes) == 0 {
		t.Fatal("expected scopes to be populated")
	}
}

func TestAuthenticate_InvalidClaims(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := "https://jwks.test/keys"
	jwks := buildJWKS(t, &privKey.PublicKey, "kid-1")
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == jwksURL {
				return jsonResponse(http.StatusOK, jwks), nil
			}
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}),
	}

	cfg := config.Config{
		OIDCIssuerURL:     "https://issuer.test",
		OIDCAudience:      "proteus-api",
		OIDCJWKSURL:       jwksURL,
		OIDCClockSkewSecs: 0,
	}
	auth, err := NewAuthenticator(cfg, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	now := time.Now().UTC()
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "missing exp",
			claims: map[string]any{
				"iss": cfg.OIDCIssuerURL,
				"aud": cfg.OIDCAudience,
				"nbf": now.Add(-1 * time.Minute).Unix(),
			},
		},
		{
			name: "expired",
			claims: map[string]any{
				"iss": cfg.OIDCIssuerURL,
				"aud": cfg.OIDCAudience,
				"exp": now.Add(-5 * time.Minute).Unix(),
				"nbf": now.Add(-10 * time.Minute).Unix(),
			},
		},
		{
			name: "nbf in future",
			claims: map[string]any{
				"iss": cfg.OIDCIssuerURL,
				"aud": cfg.OIDCAudience,
				"exp": now.Add(5 * time.Minute).Unix(),
				"nbf": now.Add(5 * time.Minute).Unix(),
			},
		},
		{
			name: "wrong issuer",
			claims: map[string]any{
				"iss": "https://wrong",
				"aud": cfg.OIDCAudience,
				"exp": now.Add(5 * time.Minute).Unix(),
			},
		},
		{
			name: "wrong audience",
			claims: map[string]any{
				"iss": cfg.OIDCIssuerURL,
				"aud": "wrong",
				"exp": now.Add(5 * time.Minute).Unix(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signToken(t, privKey, "kid-1", tc.claims)
			if _, err := auth.Authenticate(context.Background(), token); err == nil {
				t.Fatal("expected auth failure")
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func buildJWKS(t *testing.T, key *rsa.PublicKey, kid string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBytes := bigIntToBytes(key.E)
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	payload := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   n,
				"e":   e,
			},
		},
	}
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(out)
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	seg0 := base64.RawURLEncoding.EncodeToString(headerBytes)
	seg1 := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := seg0 + "." + seg1
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	seg2 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + seg2
}

func bigIntToBytes(value int) []byte {
	out := []byte{}
	for v := value; v > 0; v >>= 8 {
		out = append([]byte{byte(v & 0xff)}, out...)
	}
	if len(out) == 0 {
		return []byte{0}
	}
	return out
}
