package rekor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"proteus/internal/domain"
	"proteus/internal/infra/anchor"
)

type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (t testSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	return ed25519.Sign(t.priv, payload), t.pub, nil
}

func TestRekorAnchorSuccess(t *testing.T) {
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x01}, 32),
		Signature: bytes.Repeat([]byte{0x02}, 64),
	}
	payload, err := anchor.BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}

	var gotHash string
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/api/v1/log/entries":
				body, _ := io.ReadAll(req.Body)
				var entry hashedRekord
				if err := json.Unmarshal(body, &entry); err != nil {
					t.Fatalf("invalid rekor request: %v", err)
				}
				gotHash = entry.Spec.Data.Hash.Value
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"uuid-123":{"logIndex":7}}`))),
				}, nil
			case "/api/v1/log/entries/uuid-123":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"uuid-123":{"logIndex":7,"integratedTime":1700000000}}`))),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
		}),
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	signer := testSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}

	client, err := NewClient("https://rekor.example", "rekor_public", signer, httpClient)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	receipt := client.Anchor(context.Background(), payload)
	if receipt.Status != "anchored" {
		t.Fatalf("expected anchored, got %s", receipt.Status)
	}
	if receipt.EntryUUID != "uuid-123" {
		t.Fatalf("expected uuid-123, got %s", receipt.EntryUUID)
	}
	if receipt.LogIndex != 7 || receipt.IntegratedTime != 1700000000 {
		t.Fatalf("unexpected inclusion fields")
	}
	if len(receipt.ProviderReceiptJSON) == 0 {
		t.Fatal("expected provider receipt json")
	}
	expectedReceiptHash := sha256Hex([]byte(`{"uuid-123":{"logIndex":7,"integratedTime":1700000000}}`))
	if receipt.ProviderReceiptSHA256 != expectedReceiptHash {
		t.Fatalf("unexpected provider receipt hash: %s", receipt.ProviderReceiptSHA256)
	}
	if gotHash != payload.HashHex {
		t.Fatalf("expected payload hash %s, got %s", payload.HashHex, gotHash)
	}
}

func TestRekorAnchorNetworkFailure(t *testing.T) {
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x03}, 32),
		Signature: bytes.Repeat([]byte{0x04}, 64),
	}
	seed := bytes.Repeat([]byte{0x01}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	signer := testSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}

	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	}

	client, err := NewClient("https://rekor.example", "rekor_public", signer, httpClient)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	payload, err := anchor.BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	receipt := client.Anchor(context.Background(), payload)
	if receipt.Status != "failed" || receipt.ErrorCode != "NETWORK" {
		t.Fatalf("unexpected status/error: %s/%s", receipt.Status, receipt.ErrorCode)
	}
}

func TestRekorAnchorTruncatesReceipt(t *testing.T) {
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x05}, 32),
		Signature: bytes.Repeat([]byte{0x06}, 64),
	}

	largeBody := bytes.Repeat([]byte("a"), maxProviderReceiptBytes+10)
	entryJSON := `{"uuid-123":{"logIndex":7,"integratedTime":1700000000,"body":"` + string(largeBody) + `"}}`

	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/api/v1/log/entries":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"uuid-123":{"logIndex":7}}`))),
				}, nil
			case "/api/v1/log/entries/uuid-123":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader([]byte(entryJSON))),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
		}),
	}

	seed := bytes.Repeat([]byte{0x02}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	signer := testSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}

	client, err := NewClient("https://rekor.example", "rekor_public", signer, httpClient)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	payload, err := anchor.BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	receipt := client.Anchor(context.Background(), payload)
	if !receipt.ProviderReceiptTruncated {
		t.Fatal("expected truncated receipt")
	}
	if receipt.ProviderReceiptSizeBytes <= maxProviderReceiptBytes {
		t.Fatalf("expected size > %d, got %d", maxProviderReceiptBytes, receipt.ProviderReceiptSizeBytes)
	}
	if receipt.ProviderReceiptSizeBytes != len(entryJSON) {
		t.Fatalf("unexpected size: %d", receipt.ProviderReceiptSizeBytes)
	}
	if receipt.PayloadHash != payload.HashHex {
		t.Fatalf("expected payload hash %s, got %s", payload.HashHex, receipt.PayloadHash)
	}
	expectedReceiptHash := sha256Hex([]byte(entryJSON))
	if receipt.ProviderReceiptSHA256 != expectedReceiptHash {
		t.Fatalf("unexpected provider receipt hash: %s", receipt.ProviderReceiptSHA256)
	}
	var truncated struct {
		Truncated    bool   `json:"truncated"`
		PrefixBase64 string `json:"prefix_base64"`
	}
	if err := json.Unmarshal(receipt.ProviderReceiptJSON, &truncated); err != nil {
		t.Fatalf("decode truncated receipt: %v", err)
	}
	if !truncated.Truncated || truncated.PrefixBase64 == "" {
		t.Fatal("expected truncated payload metadata")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
