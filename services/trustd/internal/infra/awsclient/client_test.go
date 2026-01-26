package awsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"proteus/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClient_GetPutDeleteSecret(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	var targets []string

	client := New("https://secrets.example", "us-east-1", "access", "secret", "")
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method: %s", r.Method)
			}
			target := r.Header.Get("X-Amz-Target")
			targets = append(targets, target)
			if target == "" {
				t.Fatal("missing X-Amz-Target")
			}
			if r.Header.Get("X-Amz-Date") != fixed.Format("20060102T150405Z") {
				t.Fatalf("unexpected X-Amz-Date: %s", r.Header.Get("X-Amz-Date"))
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
				t.Fatalf("unexpected authorization header: %s", auth)
			}
			body, _ := io.ReadAll(r.Body)

			switch target {
			case "secretsmanager.GetSecretValue":
				var req struct {
					SecretID string `json:"SecretId"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					t.Fatalf("decode get: %v", err)
				}
				if req.SecretID != "secret-1" {
					t.Fatalf("unexpected secret id: %s", req.SecretID)
				}
				resp := map[string]string{"SecretString": "payload"}
				payload, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(payload)),
					Header:     make(http.Header),
				}, nil
			case "secretsmanager.CreateSecret":
				var req struct {
					Name         string `json:"Name"`
					SecretString string `json:"SecretString"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					t.Fatalf("decode create: %v", err)
				}
				if req.Name != "secret-1" || req.SecretString != "payload" {
					t.Fatalf("unexpected create payload: %+v", req)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			case "secretsmanager.DeleteSecret":
				var req struct {
					SecretID                   string `json:"SecretId"`
					ForceDeleteWithoutRecovery bool   `json:"ForceDeleteWithoutRecovery"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					t.Fatalf("decode delete: %v", err)
				}
				if req.SecretID != "secret-1" || !req.ForceDeleteWithoutRecovery {
					t.Fatalf("unexpected delete payload: %+v", req)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected target: %s", target)
			}
			return nil, nil
		}),
	}
	client.WithClock(func() time.Time { return fixed })

	secret, err := client.GetSecret(context.Background(), "secret-1")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret) != "payload" {
		t.Fatalf("unexpected secret: %s", string(secret))
	}
	if err := client.CreateSecret(context.Background(), "secret-1", []byte("payload")); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if err := client.DeleteSecret(context.Background(), "secret-1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(targets))
	}
}

func TestNewFromConfigRequiresConfig(t *testing.T) {
	cfg := config.Config{}
	if _, err := NewFromConfig(cfg); err == nil {
		t.Fatal("expected error for missing aws config")
	}
}
