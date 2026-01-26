//go:build integration
// +build integration

package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
	"proteus/internal/usecase"
)

func TestAuditEventRepository_Append_HashChain(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAuditEventRepository(db)
	firstTime := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	first, err := repo.Append(context.Background(), domain.AuditEvent{
		TenantID:  tenantID,
		ActorType: domain.AuditActorSystem,
		EventType: domain.AuditEventKeyRegistered,
		Payload: map[string]any{
			"tenant_id": tenantID,
			"kid":       "kid-1",
		},
		TargetType: domain.AuditTargetKey,
		TargetID:   "kid-1",
		Result:     domain.AuditResultSuccess,
		CreatedAt:  firstTime,
	})
	if err != nil {
		t.Fatalf("append first audit event: %v", err)
	}
	if first.EventHash == "" {
		t.Fatal("expected event_hash for first audit event")
	}
	if first.Seq != 1 {
		t.Fatalf("expected seq 1, got %d", first.Seq)
	}

	secondTime := time.Date(2026, 2, 1, 11, 0, 0, 0, time.UTC)
	second, err := repo.Append(context.Background(), domain.AuditEvent{
		TenantID:  tenantID,
		ActorType: domain.AuditActorSystem,
		EventType: domain.AuditEventKeyRevoked,
		Payload: map[string]any{
			"tenant_id": tenantID,
			"kid":       "kid-1",
		},
		TargetType: domain.AuditTargetKey,
		TargetID:   "kid-1",
		Result:     domain.AuditResultSuccess,
		CreatedAt:  secondTime,
	})
	if err != nil {
		t.Fatalf("append second audit event: %v", err)
	}
	if second.PrevEventHash != first.EventHash {
		t.Fatalf("expected prev_event_hash %s, got %s", first.EventHash, second.PrevEventHash)
	}
	if second.Seq != 2 {
		t.Fatalf("expected seq 2, got %d", second.Seq)
	}

	var stored AuditEventModel
	if err := db.WithContext(context.Background()).First(&stored, "id = ?", first.ID).Error; err != nil {
		t.Fatalf("load stored audit event: %v", err)
	}
	if stored.EventHash != first.EventHash {
		t.Fatal("append should not mutate previous audit event")
	}
	canonical, err := cryptoinfra.CanonicalizeAny(map[string]any{
		"tenant_id": tenantID,
		"kid":       "kid-1",
	})
	if err != nil {
		t.Fatalf("canonicalize payload: %v", err)
	}
	sum := sha256Hex(canonical)
	if stored.PayloadHash != sum {
		t.Fatalf("expected payload_hash %s, got %s", sum, stored.PayloadHash)
	}
	if _, err := hex.DecodeString(stored.EventHash); err != nil {
		t.Fatalf("invalid event hash: %v", err)
	}

	var count int64
	if err := db.WithContext(context.Background()).Model(&AuditEventModel{}).Count(&count).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 audit events, got %d", count)
	}
}

func TestAuditEventRepository_AppendOnly(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAuditEventRepository(db)
	event, err := repo.Append(context.Background(), domain.AuditEvent{
		TenantID:   tenantID,
		ActorType:  domain.AuditActorSystem,
		EventType:  domain.AuditEventKeyRegistered,
		Payload:    map[string]any{"tenant_id": tenantID, "kid": "kid-1"},
		TargetType: domain.AuditTargetKey,
		TargetID:   "kid-1",
		Result:     domain.AuditResultSuccess,
	})
	if err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	if err := db.WithContext(context.Background()).
		Exec("UPDATE audit_events SET target_id = ? WHERE id = ?", "tampered", event.ID).Error; err == nil {
		t.Fatal("expected update to fail on append-only table")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected append-only error, got %v", err)
	}
	if err := db.WithContext(context.Background()).
		Exec("DELETE FROM audit_events WHERE id = ?", event.ID).Error; err == nil {
		t.Fatal("expected delete to fail on append-only table")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected append-only error, got %v", err)
	}
}

func TestAuditEventRepository_VerifyChain(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAuditEventRepository(db)
	for i := 0; i < 3; i++ {
		_, err := repo.Append(context.Background(), domain.AuditEvent{
			TenantID:   tenantID,
			ActorType:  domain.AuditActorSystem,
			EventType:  domain.AuditEventKeyRegistered,
			Payload:    map[string]any{"tenant_id": tenantID, "kid": "kid-1"},
			TargetType: domain.AuditTargetKey,
			TargetID:   "kid-1",
			Result:     domain.AuditResultSuccess,
			CreatedAt:  time.Date(2026, 2, 1, 10+i, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("append audit event: %v", err)
		}
	}
	if err := usecase.VerifyTenantAuditChain(context.Background(), repo, tenantID); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
}

func TestAuditEventRepository_VerifyChain_MutatedPayload(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewAuditEventRepository(db)
	first, err := repo.Append(context.Background(), domain.AuditEvent{
		TenantID:   tenantID,
		ActorType:  domain.AuditActorSystem,
		EventType:  domain.AuditEventKeyRegistered,
		Payload:    map[string]any{"tenant_id": tenantID, "kid": "kid-1"},
		TargetType: domain.AuditTargetKey,
		TargetID:   "kid-1",
		Result:     domain.AuditResultSuccess,
		CreatedAt:  time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("append first audit event: %v", err)
	}

	payloadJSON, err := cryptoinfra.CanonicalizeAny(map[string]any{
		"kid":       "kid-1",
		"tenant_id": tenantID,
	})
	if err != nil {
		t.Fatalf("canonicalize payload json: %v", err)
	}
	wrongPayloadJSON, err := cryptoinfra.CanonicalizeAny(map[string]any{
		"kid":       "tampered",
		"tenant_id": tenantID,
	})
	if err != nil {
		t.Fatalf("canonicalize wrong payload: %v", err)
	}
	wrongPayloadHash := sha256Hex(wrongPayloadJSON)
	createdAt := time.Date(2026, 2, 1, 11, 0, 0, 0, time.UTC).Truncate(time.Microsecond)
	eventHash, err := computeEventHashForTest(tenantID, 2, string(domain.AuditEventKeyRegistered), wrongPayloadHash, first.EventHash, createdAt)
	if err != nil {
		t.Fatalf("compute event hash: %v", err)
	}
	model := AuditEventModel{
		ID:            mustUUID(t),
		TenantID:      tenantID,
		Seq:           2,
		EventType:     string(domain.AuditEventKeyRegistered),
		PayloadJSON:   payloadJSON,
		PayloadHash:   wrongPayloadHash,
		ActorType:     string(domain.AuditActorSystem),
		TargetType:    string(domain.AuditTargetKey),
		TargetID:      stringPtr("kid-1"),
		Result:        string(domain.AuditResultSuccess),
		PrevEventHash: first.EventHash,
		EventHash:     eventHash,
		CreatedAt:     createdAt,
	}
	if err := db.WithContext(context.Background()).Create(&model).Error; err != nil {
		t.Fatalf("insert mutated audit event: %v", err)
	}

	if err := usecase.VerifyTenantAuditChain(context.Background(), repo, tenantID); err == nil {
		t.Fatal("expected verification to fail on mutated payload")
	}
}

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func computeEventHashForTest(tenantID string, seq int64, eventType string, payloadHash string, prevHash string, createdAt time.Time) (string, error) {
	payload := map[string]any{
		"v":               domain.AuditChainVersion,
		"tenant_id":       tenantID,
		"seq":             seq,
		"event_type":      eventType,
		"payload_hash":    payloadHash,
		"prev_event_hash": prevHash,
		"created_at":      createdAt.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := cryptoinfra.CanonicalizeAny(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
