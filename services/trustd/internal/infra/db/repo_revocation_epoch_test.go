//go:build integration
// +build integration

package db

import (
	"context"
	"testing"
)

func TestRevocationEpochRepository_GetAndBump(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewRevocationEpochRepository(db)

	epoch, err := repo.GetEpoch(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get epoch: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("expected epoch 0, got %d", epoch)
	}

	epoch, err = repo.BumpEpoch(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("bump epoch: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", epoch)
	}

	epoch, err = repo.BumpEpoch(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("bump epoch again: %v", err)
	}
	if epoch != 2 {
		t.Fatalf("expected epoch 2, got %d", epoch)
	}
}
