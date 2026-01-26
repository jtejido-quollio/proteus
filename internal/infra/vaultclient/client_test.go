package vaultclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClient_ReadWriteDeleteKV(t *testing.T) {
	t.Parallel()
	const token = "vault-token"
	var (
		readCalled   bool
		writeCalled  bool
		deleteCalled bool
	)

	client := New("https://vault.example", token)
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("X-Vault-Token") != token {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			}
			switch r.Method {
			case http.MethodGet:
				readCalled = true
				if r.URL.Path != "/v1/secret/data/test" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				resp := map[string]any{
					"data": map[string]any{
						"data": map[string]string{
							"foo": "bar",
						},
					},
				}
				payload, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(payload)),
					Header:     make(http.Header),
				}, nil
			case http.MethodPut:
				writeCalled = true
				if r.URL.Path != "/v1/secret/data/test" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				var decoded map[string]map[string]string
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if decoded["data"]["foo"] != "bar" {
					t.Fatalf("unexpected payload: %v", decoded)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			case http.MethodDelete:
				deleteCalled = true
				if r.URL.Path != "/v1/secret/data/test" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusMethodNotAllowed,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			}
		}),
	}
	var out struct {
		Foo string `json:"foo"`
	}
	if err := client.ReadKV(context.Background(), "secret/data/test", &out); err != nil {
		t.Fatalf("read kv: %v", err)
	}
	if out.Foo != "bar" {
		t.Fatalf("unexpected read data: %v", out.Foo)
	}
	if err := client.WriteKV(context.Background(), "secret/data/test", map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("write kv: %v", err)
	}
	if err := client.DeleteKV(context.Background(), "secret/data/test"); err != nil {
		t.Fatalf("delete kv: %v", err)
	}
	if !readCalled || !writeCalled || !deleteCalled {
		t.Fatalf("expected read/write/delete calls, got read=%v write=%v delete=%v", readCalled, writeCalled, deleteCalled)
	}
}
