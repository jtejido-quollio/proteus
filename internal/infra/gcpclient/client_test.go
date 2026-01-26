package gcpclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"proteus/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClient_AccessAddDeleteSecret(t *testing.T) {
	const token = "token-123"
	projectID := "project-1"
	secretID := "secret-1"
	payload := []byte("hello")

	var calls []string
	client := New("https://secretmanager.example", projectID, token)
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Fatalf("unexpected auth header: %s", r.Header.Get("Authorization"))
			}
			calls = append(calls, r.Method+" "+r.URL.Path)
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/"+projectID+"/secrets/"+secretID+"/versions/latest:access":
				resp := map[string]any{
					"payload": map[string]string{
						"data": base64.StdEncoding.EncodeToString(payload),
					},
				}
				body, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/"+projectID+"/secrets/"+secretID+":addVersion":
				body, _ := io.ReadAll(r.Body)
				var req struct {
					Payload struct {
						Data string `json:"data"`
					} `json:"payload"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					t.Fatalf("decode add version: %v", err)
				}
				if req.Payload.Data != base64.StdEncoding.EncodeToString(payload) {
					t.Fatalf("unexpected payload data: %s", req.Payload.Data)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/projects/"+projectID+"/secrets/"+secretID:
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			return nil, nil
		}),
	}
	out, err := client.AccessSecret(context.Background(), secretID)
	if err != nil {
		t.Fatalf("access secret: %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("unexpected payload: %s", string(out))
	}
	if err := client.AddSecretVersion(context.Background(), secretID, payload); err != nil {
		t.Fatalf("add version: %v", err)
	}
	if err := client.DeleteSecret(context.Background(), secretID); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(calls))
	}
}

func TestNewFromConfigRequiresConfig(t *testing.T) {
	cfg := config.Config{}
	if _, err := NewFromConfig(cfg); err == nil {
		t.Fatal("expected error for missing gcp config")
	}
}
