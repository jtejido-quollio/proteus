package db

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AnchorReceiptRepository struct {
	db *gorm.DB
}

func NewAnchorReceiptRepository(db *gorm.DB) *AnchorReceiptRepository {
	return &AnchorReceiptRepository{db: db}
}

func (r *AnchorReceiptRepository) AppendAnchored(ctx context.Context, receipt domain.AnchorReceipt) error {
	if r.db == nil {
		return errDBUnavailable
	}
	if receipt.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if receipt.Provider == "" {
		return errors.New("provider is required")
	}
	if receipt.BundleID == "" {
		return errors.New("bundle_id is required")
	}
	if receipt.Status == "" {
		return errors.New("status is required")
	}
	if receipt.PayloadHash == "" {
		return errors.New("payload_hash is required")
	}
	if receipt.Status == "" {
		receipt.Status = domain.AnchorStatusAnchored
	} else if receipt.Status != domain.AnchorStatusAnchored {
		return errors.New("receipt status must be anchored")
	}

	model := AnchorReceiptModel{
		TenantID:                 receipt.TenantID,
		Provider:                 receipt.Provider,
		BundleID:                 receipt.BundleID,
		Status:                   receipt.Status,
		ErrorCode:                stringPtrIfNotEmpty(receipt.ErrorCode),
		PayloadHash:              receipt.PayloadHash,
		TreeSize:                 receipt.TreeSize,
		EntryUUID:                stringPtrIfNotEmpty(receipt.EntryUUID),
		LogIndex:                 int64Ptr(receipt.LogIndex),
		IntegratedTime:           int64Ptr(receipt.IntegratedTime),
		EntryURL:                 stringPtrIfNotEmpty(receipt.EntryURL),
		TxID:                     stringPtrIfNotEmpty(receipt.TxID),
		ChainID:                  stringPtrIfNotEmpty(receipt.ChainID),
		ExplorerURL:              stringPtrIfNotEmpty(receipt.ExplorerURL),
		ProviderReceiptJSON:      copyBytes(receipt.ProviderReceiptJSON),
		ProviderReceiptTruncated: receipt.ProviderReceiptTruncated,
		ProviderReceiptSizeBytes: receipt.ProviderReceiptSizeBytes,
		ProviderReceiptSHA256:    receipt.ProviderReceiptSHA256,
		CreatedAt:                time.Now().UTC(),
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model).Error
}

func (r *AnchorReceiptRepository) Append(ctx context.Context, receipt domain.AnchorReceipt) error {
	return r.AppendAnchored(ctx, receipt)
}

func (r *AnchorReceiptRepository) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorReceipt, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	if tenantID == "" || payloadHash == "" {
		return nil, errors.New("tenant_id and payload_hash are required")
	}
	var models []AnchorReceiptModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND payload_hash = ?", tenantID, payloadHash).
		Order("created_at ASC").
		Find(&models).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AnchorReceipt, 0, len(models))
	for _, model := range models {
		out = append(out, anchorReceiptFromModel(model))
	}
	return out, nil
}

func anchorReceiptFromModel(model AnchorReceiptModel) domain.AnchorReceipt {
	return domain.AnchorReceipt{
		TenantID:                 model.TenantID,
		Provider:                 model.Provider,
		BundleID:                 model.BundleID,
		Status:                   model.Status,
		ErrorCode:                stringValue(model.ErrorCode),
		PayloadHash:              model.PayloadHash,
		TreeSize:                 model.TreeSize,
		EntryUUID:                stringValue(model.EntryUUID),
		LogIndex:                 int64Value(model.LogIndex),
		IntegratedTime:           int64Value(model.IntegratedTime),
		EntryURL:                 stringValue(model.EntryURL),
		TxID:                     stringValue(model.TxID),
		ChainID:                  stringValue(model.ChainID),
		ExplorerURL:              stringValue(model.ExplorerURL),
		ProviderReceiptJSON:      copyBytes(model.ProviderReceiptJSON),
		ProviderReceiptTruncated: model.ProviderReceiptTruncated,
		ProviderReceiptSizeBytes: model.ProviderReceiptSizeBytes,
		ProviderReceiptSHA256:    model.ProviderReceiptSHA256,
	}
}

func int64Ptr(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}

func int64Value(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
