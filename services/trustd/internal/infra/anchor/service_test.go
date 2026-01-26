package anchor

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"proteus/internal/domain"
)

type stubProvider struct {
	id       string
	bundleID string
	receipt  domain.AnchorReceipt
	err      error
}

func (s stubProvider) BundleID() string     { return s.bundleID }
func (s stubProvider) ProviderName() string { return s.id }
func (s stubProvider) Anchor(ctx context.Context, payload Payload) domain.AnchorReceipt {
	return s.receipt
}

type stubAttemptStore struct {
	attempts []domain.AnchorAttempt
	err      error
}

func (s *stubAttemptStore) Append(ctx context.Context, attempt domain.AnchorAttempt) error {
	s.attempts = append(s.attempts, attempt)
	return s.err
}

func (s *stubAttemptStore) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorAttempt, error) {
	return s.attempts, nil
}

type stubReceiptStore struct {
	receipts []domain.AnchorReceipt
	err      error
}

func (s *stubReceiptStore) AppendAnchored(ctx context.Context, receipt domain.AnchorReceipt) error {
	s.receipts = append(s.receipts, receipt)
	return s.err
}

func (s *stubReceiptStore) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorReceipt, error) {
	return s.receipts, nil
}

func TestBuildPayloadStable(t *testing.T) {
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  4,
		RootHash:  bytes.Repeat([]byte{0x01}, 32),
		Signature: bytes.Repeat([]byte{0x02}, 64),
	}
	first, err := BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	second, err := BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload again: %v", err)
	}
	if first.HashHex != second.HashHex {
		t.Fatalf("expected stable hash, got %s vs %s", first.HashHex, second.HashHex)
	}
	if !bytes.Equal(first.CanonicalJSON, second.CanonicalJSON) {
		t.Fatal("expected stable canonical json")
	}
}

func TestServiceAnchorsDefaultProviders(t *testing.T) {
	provider := stubProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt:  domain.AnchorReceipt{Status: domain.AnchorStatusAnchored},
	}
	attempts := &stubAttemptStore{}
	receiptStore := &stubReceiptStore{}
	svc, err := NewService([]Provider{provider}, []string{"rekor"}, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x02}, 32),
		Signature: bytes.Repeat([]byte{0x03}, 64),
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Provider != "rekor" || receipts[0].BundleID != "rekor_public" {
		t.Fatal("missing provider metadata")
	}
	if receipts[0].TreeSize != sth.TreeSize {
		t.Fatalf("expected tree size %d, got %d", sth.TreeSize, receipts[0].TreeSize)
	}
	if receipts[0].PayloadHash == "" {
		t.Fatal("expected payload hash")
	}
	if len(attempts.attempts) != 1 {
		t.Fatalf("expected attempt stored, got %d", len(attempts.attempts))
	}
	if len(receiptStore.receipts) != 1 {
		t.Fatalf("expected receipt stored, got %d", len(receiptStore.receipts))
	}
}

func TestServiceOverridesProviderFields(t *testing.T) {
	provider := stubProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt: domain.AnchorReceipt{
			Status:      domain.AnchorStatusAnchored,
			PayloadHash: "bad",
		},
	}
	svc, err := NewService([]Provider{provider}, []string{"rekor"}, nil, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x08}, 32),
		Signature: bytes.Repeat([]byte{0x09}, 64),
	}
	payload, err := BuildPayload(tenantID, sth)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].PayloadHash != payload.HashHex {
		t.Fatalf("expected payload hash %s, got %s", payload.HashHex, receipts[0].PayloadHash)
	}
	if receipts[0].Provider != provider.id || receipts[0].BundleID != provider.bundleID {
		t.Fatalf("expected provider metadata, got %s/%s", receipts[0].Provider, receipts[0].BundleID)
	}
}

func TestServiceSkippedWhenNoProviders(t *testing.T) {
	attempts := &stubAttemptStore{}
	receiptStore := &stubReceiptStore{}
	svc, err := NewService(nil, nil, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x03}, 32),
		Signature: bytes.Repeat([]byte{0x04}, 64),
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != domain.AnchorStatusSkipped {
		t.Fatalf("expected skipped receipt, got %+v", receipts)
	}
	if len(attempts.attempts) != 1 {
		t.Fatalf("expected attempt stored, got %d", len(attempts.attempts))
	}
	if len(receiptStore.receipts) != 0 {
		t.Fatalf("expected no receipts stored, got %d", len(receiptStore.receipts))
	}
}

func TestServiceFailedProviderStoresAttemptOnly(t *testing.T) {
	provider := stubProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt: domain.AnchorReceipt{
			Status:    domain.AnchorStatusFailed,
			ErrorCode: domain.AnchorErrorNetwork,
		},
	}
	attempts := &stubAttemptStore{}
	receiptStore := &stubReceiptStore{}
	svc, err := NewService([]Provider{provider}, []string{"rekor"}, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x04}, 32),
		Signature: bytes.Repeat([]byte{0x05}, 64),
	}
	receiptsOut, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receiptsOut) != 1 || receiptsOut[0].Status != domain.AnchorStatusFailed {
		t.Fatalf("expected failed receipt, got %+v", receiptsOut)
	}
	if len(attempts.attempts) != 1 {
		t.Fatalf("expected attempt stored, got %d", len(attempts.attempts))
	}
	if len(receiptStore.receipts) != 0 {
		t.Fatalf("expected no receipts stored, got %d", len(receiptStore.receipts))
	}
}

type countingProvider struct {
	id       string
	bundleID string
	receipt  domain.AnchorReceipt
	calls    *int
}

func (c countingProvider) ProviderName() string { return c.id }
func (c countingProvider) BundleID() string     { return c.bundleID }
func (c countingProvider) Anchor(ctx context.Context, payload Payload) domain.AnchorReceipt {
	if c.calls != nil {
		*c.calls++
	}
	return c.receipt
}

type blockingProvider struct {
	id       string
	bundleID string
}

func (b blockingProvider) ProviderName() string { return b.id }
func (b blockingProvider) BundleID() string     { return b.bundleID }
func (b blockingProvider) Anchor(ctx context.Context, payload Payload) domain.AnchorReceipt {
	<-ctx.Done()
	return domain.AnchorReceipt{Status: domain.AnchorStatusAnchored}
}

func TestServiceAggregatesProvidersInOrder(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	first := countingProvider{
		id:       "rekor_public",
		bundleID: "rekor_public",
		receipt: domain.AnchorReceipt{
			Status:    domain.AnchorStatusFailed,
			ErrorCode: domain.AnchorErrorNetwork,
		},
		calls: &firstCalls,
	}
	second := countingProvider{
		id:       "eth_mainnet",
		bundleID: "eth_mainnet",
		receipt:  domain.AnchorReceipt{Status: domain.AnchorStatusAnchored},
		calls:    &secondCalls,
	}
	attempts := &stubAttemptStore{}
	receiptStore := &stubReceiptStore{}
	svc, err := NewService([]Provider{first, second}, []string{"rekor_public", "eth_mainnet"}, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x09}, 32),
		Signature: bytes.Repeat([]byte{0x0a}, 64),
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
	if receipts[0].Provider != "rekor_public" || receipts[1].Provider != "eth_mainnet" {
		t.Fatalf("unexpected provider order: %+v", receipts)
	}
	if receipts[0].PayloadHash == "" || receipts[0].PayloadHash != receipts[1].PayloadHash {
		t.Fatal("expected stable payload hash across receipts")
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("expected providers called once, got %d and %d", firstCalls, secondCalls)
	}
}

func TestServiceMarksPersistenceFailureOnAttempt(t *testing.T) {
	provider := stubProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt:  domain.AnchorReceipt{Status: domain.AnchorStatusAnchored},
	}
	attempts := &stubAttemptStore{err: errors.New("attempt insert failed")}
	receiptStore := &stubReceiptStore{}
	svc, err := NewService([]Provider{provider}, []string{"rekor"}, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x06}, 32),
		Signature: bytes.Repeat([]byte{0x07}, 64),
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != domain.AnchorStatusFailed || receipts[0].ErrorCode != domain.AnchorErrorPersistence {
		t.Fatalf("expected persistence failure, got %s/%s", receipts[0].Status, receipts[0].ErrorCode)
	}
}

func TestServiceMarksPersistenceFailureOnReceipt(t *testing.T) {
	provider := stubProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt:  domain.AnchorReceipt{Status: domain.AnchorStatusAnchored},
	}
	attempts := &stubAttemptStore{}
	receiptStore := &stubReceiptStore{err: errors.New("receipt insert failed")}
	svc, err := NewService([]Provider{provider}, []string{"rekor"}, attempts, receiptStore)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x07}, 32),
		Signature: bytes.Repeat([]byte{0x08}, 64),
	}
	receipts, err := svc.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != domain.AnchorStatusFailed || receipts[0].ErrorCode != domain.AnchorErrorPersistence {
		t.Fatalf("expected persistence failure, got %s/%s", receipts[0].Status, receipts[0].ErrorCode)
	}
}

func TestServiceMarksTimeoutFailure(t *testing.T) {
	provider := blockingProvider{
		id:       "rekor",
		bundleID: "rekor_public",
	}
	tenantID := "tenant-1"
	sth := domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x09}, 32),
		Signature: bytes.Repeat([]byte{0x0a}, 64),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	svc, err := NewService([]Provider{provider}, []string{"rekor"}, nil, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	receipts, err := svc.AnchorSTH(ctx, tenantID, sth)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != domain.AnchorStatusFailed || receipts[0].ErrorCode != domain.AnchorErrorTimeout {
		t.Fatalf("expected timeout failure, got %s/%s", receipts[0].Status, receipts[0].ErrorCode)
	}
}
