package db

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
)

type AnchorAttemptRepository struct {
	db *gorm.DB
}

func NewAnchorAttemptRepository(db *gorm.DB) *AnchorAttemptRepository {
	return &AnchorAttemptRepository{db: db}
}

func (r *AnchorAttemptRepository) Append(ctx context.Context, attempt domain.AnchorAttempt) error {
	if r.db == nil {
		return errDBUnavailable
	}
	if attempt.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if attempt.Provider == "" {
		return errors.New("provider is required")
	}
	if attempt.BundleID == "" {
		return errors.New("bundle_id is required")
	}
	if attempt.Status == "" {
		return errors.New("status is required")
	}
	if attempt.PayloadHash == "" {
		return errors.New("payload_hash is required")
	}

	model := AnchorAttemptModel{
		TenantID:                 attempt.TenantID,
		TreeSize:                 attempt.TreeSize,
		Provider:                 attempt.Provider,
		BundleID:                 attempt.BundleID,
		Status:                   attempt.Status,
		ErrorCode:                stringPtrIfNotEmpty(attempt.ErrorCode),
		PayloadHash:              attempt.PayloadHash,
		ProviderReceiptJSON:      copyBytes(attempt.ProviderReceiptJSON),
		ProviderReceiptTruncated: attempt.ProviderReceiptTruncated,
		ProviderReceiptSizeBytes: attempt.ProviderReceiptSizeBytes,
		CreatedAt:                time.Now().UTC(),
	}
	return r.db.WithContext(ctx).Create(&model).Error
}

func (r *AnchorAttemptRepository) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorAttempt, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	if tenantID == "" || payloadHash == "" {
		return nil, errors.New("tenant_id and payload_hash are required")
	}
	var models []AnchorAttemptModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND payload_hash = ?", tenantID, payloadHash).
		Order("created_at ASC").
		Find(&models).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AnchorAttempt, 0, len(models))
	for _, model := range models {
		out = append(out, anchorAttemptFromModel(model))
	}
	return out, nil
}

func anchorAttemptFromModel(model AnchorAttemptModel) domain.AnchorAttempt {
	return domain.AnchorAttempt{
		TenantID:                 model.TenantID,
		TreeSize:                 model.TreeSize,
		Provider:                 model.Provider,
		BundleID:                 model.BundleID,
		Status:                   model.Status,
		ErrorCode:                stringValue(model.ErrorCode),
		PayloadHash:              model.PayloadHash,
		ProviderReceiptJSON:      copyBytes(model.ProviderReceiptJSON),
		ProviderReceiptTruncated: model.ProviderReceiptTruncated,
		ProviderReceiptSizeBytes: model.ProviderReceiptSizeBytes,
		CreatedAt:                model.CreatedAt,
	}
}
