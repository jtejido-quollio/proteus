package usecase

import (
	"context"
	"testing"
	"time"

	"proteus/internal/domain"
)

type auditChainRepoStub struct {
	events []domain.AuditEvent
}

func (r *auditChainRepoStub) Append(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	r.events = append(r.events, event)
	return event, nil
}

func (r *auditChainRepoStub) ListByTenant(ctx context.Context, tenantID string) ([]domain.AuditEvent, error) {
	return r.events, nil
}

func TestVerifyTenantAuditChain_OK(t *testing.T) {
	tenantID := "tenant-1"
	repo := &auditChainRepoStub{}
	prev := zeroAuditHash()
	for i := 1; i <= 3; i++ {
		event := buildAuditEvent(tenantID, int64(i), prev, []byte(`{"kid":"kid-1","tenant_id":"tenant-1"}`))
		repo.events = append(repo.events, event)
		prev = event.EventHash
	}
	if err := VerifyTenantAuditChain(context.Background(), repo, tenantID); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
}

func TestVerifyTenantAuditChain_Mutation(t *testing.T) {
	tenantID := "tenant-1"
	repo := &auditChainRepoStub{}
	event := buildAuditEvent(tenantID, 1, zeroAuditHash(), []byte(`{"kid":"kid-1","tenant_id":"tenant-1"}`))
	event.Payload = []byte(`{"kid":"tampered","tenant_id":"tenant-1"}`)
	repo.events = append(repo.events, event)
	if err := VerifyTenantAuditChain(context.Background(), repo, tenantID); err == nil {
		t.Fatal("expected verification to fail on payload mutation")
	}
}

func TestVerifyTenantAuditChain_SeqGap(t *testing.T) {
	tenantID := "tenant-1"
	repo := &auditChainRepoStub{}
	event := buildAuditEvent(tenantID, 2, zeroAuditHash(), []byte(`{"kid":"kid-1","tenant_id":"tenant-1"}`))
	repo.events = append(repo.events, event)
	if err := VerifyTenantAuditChain(context.Background(), repo, tenantID); err == nil {
		t.Fatal("expected verification to fail on seq gap")
	}
}

func TestVerifyTenantAuditChain_Reordered(t *testing.T) {
	tenantID := "tenant-1"
	repo := &auditChainRepoStub{}
	first := buildAuditEvent(tenantID, 1, zeroAuditHash(), []byte(`{"kid":"kid-1","tenant_id":"tenant-1"}`))
	second := buildAuditEvent(tenantID, 2, first.EventHash, []byte(`{"kid":"kid-2","tenant_id":"tenant-1"}`))
	repo.events = []domain.AuditEvent{second, first}
	if err := VerifyTenantAuditChain(context.Background(), repo, tenantID); err == nil {
		t.Fatal("expected verification to fail on reordered events")
	}
}

func buildAuditEvent(tenantID string, seq int64, prevHash string, payload []byte) domain.AuditEvent {
	event := domain.AuditEvent{
		TenantID:      tenantID,
		Seq:           seq,
		EventType:     domain.AuditEventKeyRegistered,
		Payload:       payload,
		PayloadHash:   sha256Hex(payload),
		ActorType:     domain.AuditActorSystem,
		TargetType:    domain.AuditTargetKey,
		TargetID:      "kid-1",
		Result:        domain.AuditResultSuccess,
		PrevEventHash: prevHash,
		CreatedAt:     time.Date(2026, 2, 1, 10, int(seq), 0, 0, time.UTC),
	}
	hash, _ := computeChainHash(event)
	event.EventHash = hash
	return event
}
