//go:build integration
// +build integration

package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKeycloakOIDC_RecordFlow(t *testing.T) {
	keycloakURL := envDefault("KEYCLOAK_URL", "http://localhost:8081")
	trustdURL := envDefault("TRUSTD_URL", "http://localhost:8080")
	expectedIssuer := envDefault("OIDC_ISSUER_URL", "http://keycloak:8080/realms/proteus")
	adminKey := envDefault("ADMIN_API_KEY", "dev-admin-key")
	clientID := envDefault("OIDC_CLIENT_ID", "proteus-api")
	clientSecret := envDefault("OIDC_CLIENT_SECRET", "proteus-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForKeycloak(ctx, keycloakURL); err != nil {
		t.Fatalf("keycloak not ready: %v", err)
	}
	if err := waitForTrustd(ctx, trustdURL); err != nil {
		t.Fatalf("trustd not ready: %v", err)
	}

	issuer, err := fetchIssuer(keycloakURL)
	if err != nil {
		t.Fatalf("fetch issuer: %v", err)
	}
	if issuer != expectedIssuer {
		t.Fatalf("issuer mismatch: got %s want %s", issuer, expectedIssuer)
	}

	token, err := mintToken(keycloakURL, clientID, clientSecret)
	if err != nil {
		t.Fatalf("mint token: %v (run `podman compose down -v` to reimport realm if needed)", err)
	}
	claims, err := decodeTokenClaims(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if iss, _ := claims["iss"].(string); iss != expectedIssuer {
		t.Fatalf("token issuer mismatch: got %s want %s", iss, expectedIssuer)
	}

	keys := loadKeys(t)
	envelopeBytes := readVectorFile(t, "envelope_1.json")

	if err := ensureTenant(trustdURL, adminKey, token, keys.TenantID); err != nil {
		t.Fatalf("ensure tenant: %v", err)
	}
	if err := ensureKey(trustdURL, adminKey, token, keys.TenantID, "signing", keys.KID, keys.Alg, keys.PublicKeyBase64); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}
	if err := ensureKey(trustdURL, adminKey, token, keys.TenantID, "log", "log-key-001", keys.Alg, keys.PublicKeyBase64); err != nil {
		t.Fatalf("ensure log key: %v", err)
	}

	recordURL := trustdURL + "/v1/manifests:record"
	req, err := http.NewRequest(http.MethodPost, recordURL, bytes.NewReader(envelopeBytes))
	if err != nil {
		t.Fatalf("record request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("record request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("record failed: %d %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
}

func fetchIssuer(baseURL string) (string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/realms/proteus/.well-known/openid-configuration"
	resp, err := http.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("issuer discovery failed")
	}
	var payload struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Issuer == "" {
		return "", errors.New("issuer missing")
	}
	return payload.Issuer, nil
}

func waitForKeycloak(ctx context.Context, baseURL string) error {
	for {
		_, err := fetchIssuer(baseURL)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForTrustd(ctx context.Context, baseURL string) error {
	endpoint := strings.TrimRight(baseURL, "/") + "/healthz"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func mintToken(baseURL, clientID, clientSecret string) (string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/realms/proteus/protocol/openid-connect/token"
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "client_credentials")
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = "token request failed"
		}
		return "", errors.New(msg)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("access_token missing")
	}
	return payload.AccessToken, nil
}

func decodeTokenClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func ensureTenant(baseURL, adminKey, token, tenantID string) error {
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/tenants"
	payload := map[string]string{
		"tenant_id": tenantID,
		"name":      "tenant-" + tenantID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := adminPost(endpoint, adminKey, token, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(payload))
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(msg, "duplicate key") || strings.Contains(msg, "tenants_pkey")) {
			return nil
		}
		return errors.New("create tenant failed: " + resp.Status + " " + msg)
	}
	return nil
}

func ensureKey(baseURL, adminKey, token, tenantID, purpose, kid, alg, pubKey string) error {
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/tenants/" + tenantID + "/keys/" + purpose
	payload := map[string]string{
		"kid":        kid,
		"alg":        alg,
		"public_key": pubKey,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := adminPost(endpoint, adminKey, token, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(payload))
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(msg, "duplicate key") || strings.Contains(msg, "signing_keys_tenant_id_kid_key")) {
			return ensureExistingKeyMatches(baseURL, token, tenantID, purpose, kid, pubKey)
		}
		return errors.New("register key failed: " + resp.Status + " " + msg)
	}
	return nil
}

func adminPost(endpoint, adminKey, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	return http.DefaultClient.Do(req)
}

func ensureExistingKeyMatches(baseURL, token, tenantID, purpose, kid, pubKey string) error {
	keys, err := listKeys(baseURL, token, tenantID, purpose)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.KID == kid {
			if key.PublicKey != pubKey {
				return errors.New("existing key does not match expected public key; reset DB (podman compose down -v)")
			}
			return nil
		}
	}
	return errors.New("existing key not found; reset DB (podman compose down -v)")
}

func listKeys(baseURL, token, tenantID, purpose string) ([]keyResponse, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/tenants/" + tenantID + "/keys/" + purpose
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		return nil, errors.New("list keys failed: " + resp.Status + " " + strings.TrimSpace(string(payload)))
	}
	var out []keyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func envDefault(key, def string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	return value
}
