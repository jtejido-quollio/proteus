package usecase

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"
)

type auditRepoStub struct {
	events []domain.AuditEvent
}

func (r *auditRepoStub) Append(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	r.events = append(r.events, event)
	return event, nil
}

func (r *auditRepoStub) ListByTenant(ctx context.Context, tenantID string) ([]domain.AuditEvent, error) {
	out := make([]domain.AuditEvent, 0)
	for _, event := range r.events {
		if event.TenantID == tenantID {
			out = append(out, event)
		}
	}
	return out, nil
}

func TestAuditEmitter_KeyRegistered_NoPII(t *testing.T) {
	repo := &auditRepoStub{}
	emitter := NewAuditEmitter(repo, func() time.Time {
		return time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	})

	adminKey := "super-secret-admin-key"
	if err := emitter.EmitKeyRegistered(context.Background(), domain.AuditActorAdminAPIKey, adminKey, "tenant-1", domain.KeyPurposeSigning, "kid-1", domain.AuditResultSuccess, ""); err != nil {
		t.Fatalf("emit audit event: %v", err)
	}
	if len(repo.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(repo.events))
	}
	event := repo.events[0]
	if event.ActorIDHash == "" || event.ActorIDHash == adminKey {
		t.Fatal("expected actor_id_hash to be hashed")
	}
	if _, err := hex.DecodeString(event.ActorIDHash); err != nil || len(event.ActorIDHash) != 64 {
		t.Fatal("actor_id_hash must be lowercase sha256 hex")
	}
	if strings.Contains(event.TenantID, adminKey) || strings.Contains(event.TargetID, adminKey) || strings.Contains(event.ErrorCode, adminKey) {
		t.Fatal("event fields should not contain raw admin key")
	}
	payloadMap, ok := event.Payload.(map[string]any)
	if !ok {
		t.Fatal("expected payload to be a map")
	}
	if containsPII(payloadMap, adminKey) {
		t.Fatal("payload should not contain raw admin key")
	}
	if event.TargetID != "kid-1" {
		t.Fatalf("expected target id kid-1, got %s", event.TargetID)
	}
}

func containsPII(payload map[string]any, secret string) bool {
	for _, value := range payload {
		switch v := value.(type) {
		case string:
			if strings.Contains(v, secret) {
				return true
			}
		case map[string]any:
			if containsPII(v, secret) {
				return true
			}
		}
	}
	return false
}
