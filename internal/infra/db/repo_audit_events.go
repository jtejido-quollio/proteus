package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"

	"gorm.io/gorm"
)

type AuditEventRepository struct {
	db *gorm.DB
}

func NewAuditEventRepository(db *gorm.DB) *AuditEventRepository {
	return &AuditEventRepository{db: db}
}

func (r *AuditEventRepository) Append(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	if r.db == nil {
		return domain.AuditEvent{}, errDBUnavailable
	}
	if event.ID == "" {
		id, err := newUUID()
		if err != nil {
			return domain.AuditEvent{}, err
		}
		event.ID = id
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	event.CreatedAt = event.CreatedAt.Truncate(time.Microsecond)
	if event.EventType == "" {
		return domain.AuditEvent{}, errors.New("event_type is required")
	}
	if event.TenantID == "" {
		event.TenantID = domain.AuditSystemTenantID
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}

	payloadJSON, payloadHash, err := computePayload(event.Payload)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	event.PayloadHash = payloadHash

	var out domain.AuditEvent
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		seq, prevHash, err := nextAuditSeq(ctx, tx, event.TenantID)
		if err != nil {
			return err
		}
		event.Seq = seq
		event.PrevEventHash = prevHash

		eventHash, err := computeAuditEventHash(event)
		if err != nil {
			return err
		}
		event.EventHash = eventHash

		model := auditEventModelFromDomain(event, payloadJSON)
		if err := tx.Create(&model).Error; err != nil {
			return err
		}
		out = event
		return nil
	})
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return out, nil
}

func (r *AuditEventRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.AuditEvent, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	if tenantID == "" {
		tenantID = domain.AuditSystemTenantID
	}
	var models []AuditEventModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("seq ASC").
		Find(&models).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AuditEvent, 0, len(models))
	for _, model := range models {
		canonical, err := cryptoinfra.CanonicalizeJSON(model.PayloadJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, auditEventFromModel(model, canonical))
	}
	return out, nil
}

func auditEventModelFromDomain(event domain.AuditEvent, payloadJSON []byte) AuditEventModel {
	return AuditEventModel{
		ID:            event.ID,
		TenantID:      event.TenantID,
		Seq:           event.Seq,
		EventType:     string(event.EventType),
		PayloadJSON:   payloadJSON,
		PayloadHash:   event.PayloadHash,
		ActorType:     string(event.ActorType),
		ActorIDHash:   stringPtrIfNotEmpty(event.ActorIDHash),
		TargetType:    string(event.TargetType),
		TargetID:      stringPtrIfNotEmpty(event.TargetID),
		Result:        string(event.Result),
		ErrorCode:     stringPtrIfNotEmpty(event.ErrorCode),
		PrevEventHash: event.PrevEventHash,
		EventHash:     event.EventHash,
		CreatedAt:     event.CreatedAt.UTC(),
	}
}

func auditEventFromModel(model AuditEventModel, payloadJSON []byte) domain.AuditEvent {
	return domain.AuditEvent{
		ID:            model.ID,
		TenantID:      model.TenantID,
		Seq:           model.Seq,
		EventType:     domain.AuditEventType(model.EventType),
		Payload:       payloadJSON,
		PayloadHash:   model.PayloadHash,
		ActorType:     domain.AuditActorType(model.ActorType),
		ActorIDHash:   stringValue(model.ActorIDHash),
		TargetType:    domain.AuditTargetType(model.TargetType),
		TargetID:      stringValue(model.TargetID),
		Result:        domain.AuditResult(model.Result),
		ErrorCode:     stringValue(model.ErrorCode),
		PrevEventHash: model.PrevEventHash,
		EventHash:     model.EventHash,
		CreatedAt:     model.CreatedAt.UTC(),
	}
}

func computePayload(payload any) ([]byte, string, error) {
	canonical, err := cryptoinfra.CanonicalizeAny(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

func computeAuditEventHash(event domain.AuditEvent) (string, error) {
	if event.PayloadHash == "" {
		return "", errors.New("payload_hash is required")
	}
	if event.PrevEventHash == "" {
		return "", errors.New("prev_event_hash is required")
	}
	payload := map[string]any{
		"v":               domain.AuditChainVersion,
		"tenant_id":       event.TenantID,
		"seq":             event.Seq,
		"event_type":      string(event.EventType),
		"payload_hash":    event.PayloadHash,
		"prev_event_hash": event.PrevEventHash,
		"created_at":      event.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := cryptoinfra.CanonicalizeAny(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func nextAuditSeq(ctx context.Context, tx *gorm.DB, tenantID string) (int64, string, error) {
	if tenantID == "" {
		return 0, "", errors.New("tenant_id is required")
	}
	if err := tx.WithContext(ctx).Exec(
		"INSERT INTO tenant_audit_seq (tenant_id, seq) VALUES (?, 0) ON CONFLICT (tenant_id) DO NOTHING",
		tenantID,
	).Error; err != nil {
		return 0, "", err
	}

	var currentSeq int64
	if err := tx.WithContext(ctx).Raw(
		"SELECT seq FROM tenant_audit_seq WHERE tenant_id = ? FOR UPDATE",
		tenantID,
	).Scan(&currentSeq).Error; err != nil {
		return 0, "", err
	}
	nextSeq := currentSeq + 1
	if err := tx.WithContext(ctx).Exec(
		"UPDATE tenant_audit_seq SET seq = ? WHERE tenant_id = ?",
		nextSeq,
		tenantID,
	).Error; err != nil {
		return 0, "", err
	}

	prevHash := zeroAuditHash()
	if currentSeq > 0 {
		var prev AuditEventModel
		if err := tx.WithContext(ctx).
			Where("tenant_id = ? AND seq = ?", tenantID, currentSeq).
			Take(&prev).Error; err != nil {
			return 0, "", err
		}
		prevHash = prev.EventHash
	}
	if prevHash == "" {
		return 0, "", fmt.Errorf("missing previous event hash for tenant %s", tenantID)
	}
	return nextSeq, prevHash, nil
}

func zeroAuditHash() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func stringPtrIfNotEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
