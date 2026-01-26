package db

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type RevocationEpochRepository struct {
	db *gorm.DB
}

func NewRevocationEpochRepository(db *gorm.DB) *RevocationEpochRepository {
	return &RevocationEpochRepository{db: db}
}

func (r *RevocationEpochRepository) GetEpoch(ctx context.Context, tenantID string) (int64, error) {
	if r.db == nil {
		return 0, errDBUnavailable
	}
	if tenantID == "" {
		return 0, errors.New("tenant_id is required")
	}
	// Ensure row exists with epoch 0.
	if err := r.db.WithContext(ctx).Exec(
		`INSERT INTO tenant_revocation_epoch (tenant_id, epoch, updated_at)
		 VALUES (?, 0, ?)
		 ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID,
		time.Now().UTC(),
	).Error; err != nil {
		return 0, err
	}
	var epoch int64
	if err := r.db.WithContext(ctx).
		Raw(`SELECT epoch FROM tenant_revocation_epoch WHERE tenant_id = ?`, tenantID).
		Scan(&epoch).Error; err != nil {
		return 0, err
	}
	return epoch, nil
}

func (r *RevocationEpochRepository) BumpEpoch(ctx context.Context, tenantID string) (int64, error) {
	if r.db == nil {
		return 0, errDBUnavailable
	}
	if tenantID == "" {
		return 0, errors.New("tenant_id is required")
	}
	var epoch int64
	if err := r.db.WithContext(ctx).
		Raw(
			`INSERT INTO tenant_revocation_epoch (tenant_id, epoch, updated_at)
			 VALUES (?, 1, ?)
			 ON CONFLICT (tenant_id)
			 DO UPDATE SET epoch = tenant_revocation_epoch.epoch + 1, updated_at = EXCLUDED.updated_at
			 RETURNING epoch`,
			tenantID,
			time.Now().UTC(),
		).Scan(&epoch).Error; err != nil {
		return 0, err
	}
	return epoch, nil
}
