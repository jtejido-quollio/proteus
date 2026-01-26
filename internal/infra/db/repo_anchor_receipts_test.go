//go:build integration
// +build integration

package db

import (
	"context"
	"strings"
	"testing"

	"proteus/internal/domain"
)

func TestAnchorReceiptRepository_AppendList(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAnchorReceiptRepository(db)
	receipt := domain.AnchorReceipt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusAnchored,
		PayloadHash: "deadbeef",
		TreeSize:    1,
		EntryUUID:   "uuid-1",
		LogIndex:    7,
	}
	if err := repo.AppendAnchored(context.Background(), receipt); err != nil {
		t.Fatalf("append receipt: %v", err)
	}

	list, err := repo.ListByPayloadHash(context.Background(), tenantID, "deadbeef")
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(list))
	}
	if list[0].Provider != "rekor" || list[0].EntryUUID != "uuid-1" {
		t.Fatal("unexpected receipt data")
	}
}

func TestAnchorReceiptRepository_AppendOnlyAndUnique(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAnchorReceiptRepository(db)
	receipt := domain.AnchorReceipt{
		TenantID:    tenantID,
		Provider:    "rekor",
		BundleID:    "rekor_public",
		Status:      domain.AnchorStatusAnchored,
		PayloadHash: "deadbeef",
		TreeSize:    2,
		EntryUUID:   "uuid-1",
	}
	if err := repo.AppendAnchored(context.Background(), receipt); err != nil {
		t.Fatalf("append receipt: %v", err)
	}

	var stored AnchorReceiptModel
	if err := db.WithContext(context.Background()).First(&stored).Error; err != nil {
		t.Fatalf("load receipt: %v", err)
	}

	if err := db.Exec("UPDATE anchor_receipts SET bundle_id = 'tampered' WHERE id = ?", stored.ID).Error; err == nil {
		t.Fatal("expected update to fail")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected update error: %v", err)
	}
	if err := db.Exec("DELETE FROM anchor_receipts WHERE id = ?", stored.ID).Error; err == nil {
		t.Fatal("expected delete to fail")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected delete error: %v", err)
	}

	if err := repo.AppendAnchored(context.Background(), receipt); err != nil {
		t.Fatalf("expected duplicate insert to be ignored, got %v", err)
	}

	list, err := repo.ListByPayloadHash(context.Background(), tenantID, "deadbeef")
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 receipt after duplicate insert, got %d", len(list))
	}
}
