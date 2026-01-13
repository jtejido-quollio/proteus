package db

import (
	"context"
	"errors"

	"proteus/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RevocationRepository struct {
	db *gorm.DB
}

func NewRevocationRepository(db *gorm.DB) *RevocationRepository {
	return &RevocationRepository{db: db}
}

func (r *RevocationRepository) IsRevoked(ctx context.Context, tenantID, kid string) (bool, error) {
	if r.db == nil {
		return false, errDBUnavailable
	}
	var count int64
	err := r.db.WithContext(ctx).
		Model(&RevocationModel{}).
		Where("tenant_id = ? AND kid = ?", tenantID, kid).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *RevocationRepository) Revoke(ctx context.Context, rev domain.Revocation) error {
	if r.db == nil {
		return errDBUnavailable
	}
	revID := rev.ID
	if revID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		revID = id
	}

	model := RevocationModel{
		ID:        revID,
		TenantID:  rev.TenantID,
		KID:       rev.KID,
		RevokedAt: rev.RevokedAt,
		Reason:    rev.Reason,
		CreatedAt: rev.CreatedAt,
	}
	err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	return err
}
