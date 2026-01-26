package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"proteus/internal/domain"
)

type AuditEmitter struct {
	Repo  AuditEventRepository
	Clock Clock
}

func NewAuditEmitter(repo AuditEventRepository, clock Clock) *AuditEmitter {
	return &AuditEmitter{
		Repo:  repo,
		Clock: clock,
	}
}

func (e *AuditEmitter) Emit(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	if e == nil || e.Repo == nil {
		return domain.AuditEvent{}, errors.New("audit repository required")
	}
	if event.EventType == "" || event.TargetType == "" || event.Result == "" || event.ActorType == "" {
		return domain.AuditEvent{}, errors.New("audit event missing required fields")
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = e.now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	return e.Repo.Append(ctx, event)
}

func (e *AuditEmitter) EmitKeyRegistered(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, purpose domain.KeyPurpose, kid string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"purpose":   string(purpose),
		"kid":       kid,
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventKeyRegistered,
		Payload:     payload,
		TargetType:  domain.AuditTargetKey,
		TargetID:    kid,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) EmitKeyRotated(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, purpose domain.KeyPurpose, newKID string, previousKID string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"purpose":   string(purpose),
		"kid":       newKID,
	}
	if previousKID != "" {
		payload["previous_kid"] = previousKID
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventKeyRotated,
		Payload:     payload,
		TargetType:  domain.AuditTargetKey,
		TargetID:    newKID,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) EmitKeyRevoked(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, kid string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"kid":       kid,
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventKeyRevoked,
		Payload:     payload,
		TargetType:  domain.AuditTargetKey,
		TargetID:    kid,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) EmitPolicyBundleUpserted(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, bundleID string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"bundle_id": bundleID,
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventPolicyBundleUpserted,
		Payload:     payload,
		TargetType:  domain.AuditTargetPolicyBundle,
		TargetID:    bundleID,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) EmitPolicyBundleActivated(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, bundleID string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"bundle_id": bundleID,
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventPolicyBundleActivated,
		Payload:     payload,
		TargetType:  domain.AuditTargetPolicyBundle,
		TargetID:    bundleID,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) EmitBundleExported(ctx context.Context, actorType domain.AuditActorType, actorID string, tenantID string, bundleID string, receiptDigest string, replayInputsDigest string, result domain.AuditResult, errorCode string) error {
	payload := map[string]any{
		"tenant_id": tenantID,
		"bundle_id": bundleID,
	}
	if receiptDigest != "" {
		payload["receipt_digest"] = receiptDigest
	}
	if replayInputsDigest != "" {
		payload["replay_inputs_digest"] = replayInputsDigest
	}
	_, err := e.Emit(ctx, domain.AuditEvent{
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorIDHash: hashString(actorID),
		EventType:   domain.AuditEventBundleExported,
		Payload:     payload,
		TargetType:  domain.AuditTargetBundle,
		TargetID:    bundleID,
		Result:      result,
		ErrorCode:   errorCode,
	})
	return err
}

func (e *AuditEmitter) now() time.Time {
	if e != nil && e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}

func hashString(value string) string {
	if value == "" {
		return ""
	}
	return sha256HexString([]byte(value))
}

func sha256HexString(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}
