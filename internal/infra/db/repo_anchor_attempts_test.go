//go:build integration
// +build integration

package db

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"proteus/internal/domain"
	"proteus/internal/infra/anchor"
)

func TestAnchorAttemptRepository_AppendList(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAnchorAttemptRepository(db)
	attempt := domain.AnchorAttempt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusFailed,
		ErrorCode:   domain.AnchorErrorNetwork,
		PayloadHash: "deadbeef",
		TreeSize:    1,
	}
	if err := repo.Append(context.Background(), attempt); err != nil {
		t.Fatalf("append attempt: %v", err)
	}

	list, err := repo.ListByPayloadHash(context.Background(), tenantID, "deadbeef")
	if err != nil {
		t.Fatalf("list attempts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(list))
	}
	if list[0].Status != domain.AnchorStatusFailed {
		t.Fatalf("unexpected status: %s", list[0].Status)
	}
}

func TestAnchorAttemptRepository_AppendOnly(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAnchorAttemptRepository(db)
	attempt := domain.AnchorAttempt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusFailed,
		ErrorCode:   domain.AnchorErrorNetwork,
		PayloadHash: "deadbeef",
		TreeSize:    2,
	}
	if err := repo.Append(context.Background(), attempt); err != nil {
		t.Fatalf("append attempt: %v", err)
	}

	var stored AnchorAttemptModel
	if err := db.WithContext(context.Background()).First(&stored).Error; err != nil {
		t.Fatalf("load attempt: %v", err)
	}

	if err := db.Exec("UPDATE anchor_attempts SET bundle_id = 'tampered' WHERE id = ?", stored.ID).Error; err == nil {
		t.Fatal("expected update to fail")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected update error: %v", err)
	}
	if err := db.Exec("DELETE FROM anchor_attempts WHERE id = ?", stored.ID).Error; err == nil {
		t.Fatal("expected delete to fail")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected delete error: %v", err)
	}
}

func TestAnchorAttemptDoesNotBlockReceipt(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	attemptRepo := NewAnchorAttemptRepository(db)
	receiptRepo := NewAnchorReceiptRepository(db)

	attempt := domain.AnchorAttempt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusFailed,
		ErrorCode:   domain.AnchorErrorNetwork,
		PayloadHash: "deadbeef",
		TreeSize:    3,
	}
	if err := attemptRepo.Append(context.Background(), attempt); err != nil {
		t.Fatalf("append attempt: %v", err)
	}

	receipt := domain.AnchorReceipt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusAnchored,
		PayloadHash: "deadbeef",
		TreeSize:    3,
		EntryUUID:   "uuid-1",
	}
	if err := receiptRepo.AppendAnchored(context.Background(), receipt); err != nil {
		t.Fatalf("append receipt: %v", err)
	}

	list, err := receiptRepo.ListByPayloadHash(context.Background(), tenantID, "deadbeef")
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(list))
	}
}

type sequenceProvider struct {
	id       string
	bundleID string
	receipts []domain.AnchorReceipt
	idx      int
}

func (s *sequenceProvider) ProviderName() string { return s.id }
func (s *sequenceProvider) BundleID() string     { return s.bundleID }
func (s *sequenceProvider) Anchor(ctx context.Context, payload anchor.Payload) domain.AnchorReceipt {
	if s.idx >= len(s.receipts) {
		return domain.AnchorReceipt{Status: domain.AnchorStatusFailed, ErrorCode: domain.AnchorErrorProviderError}
	}
	receipt := s.receipts[s.idx]
	s.idx++
	return receipt
}

func TestAnchorServiceFailureThenSuccess(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	attemptRepo := NewAnchorAttemptRepository(db)
	receiptRepo := NewAnchorReceiptRepository(db)

	provider := &sequenceProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipts: []domain.AnchorReceipt{
			{Status: domain.AnchorStatusFailed, ErrorCode: domain.AnchorErrorNetwork},
			{Status: domain.AnchorStatusAnchored, EntryUUID: "uuid-1"},
		},
	}
	service, err := anchor.NewService([]anchor.Provider{provider}, []string{"rekor"}, attemptRepo, receiptRepo)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	sth := domain.STH{
		TreeSize:  3,
		RootHash:  bytes.Repeat([]byte{0x0a}, 32),
		Signature: bytes.Repeat([]byte{0x0b}, 64),
	}

	first, err := service.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor first: %v", err)
	}
	if len(first) != 1 || first[0].Status != domain.AnchorStatusFailed {
		t.Fatalf("expected failed receipt, got %+v", first)
	}

	second, err := service.AnchorSTH(context.Background(), tenantID, sth)
	if err != nil {
		t.Fatalf("anchor second: %v", err)
	}
	if len(second) != 1 || second[0].Status != domain.AnchorStatusAnchored {
		t.Fatalf("expected anchored receipt, got %+v", second)
	}

	attempts, err := attemptRepo.ListByPayloadHash(context.Background(), tenantID, second[0].PayloadHash)
	if err != nil {
		t.Fatalf("list attempts: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}

	receipts, err := receiptRepo.ListByPayloadHash(context.Background(), tenantID, second[0].PayloadHash)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != domain.AnchorStatusAnchored {
		t.Fatalf("unexpected receipt status: %s", receipts[0].Status)
	}
}
