package db

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
)

type TransparencyLogRepository struct {
	db *gorm.DB
}

func NewTransparencyLogRepository(db *gorm.DB) *TransparencyLogRepository {
	return &TransparencyLogRepository{db: db}
}

func (r *TransparencyLogRepository) AppendLeaf(ctx context.Context, tenantID string, signedManifestID string, leafHash []byte) (int64, error) {
	if r.db == nil {
		return 0, errDBUnavailable
	}
	var leaf TransparencyLeafModel
	tx := r.db.WithContext(ctx).Begin()
	if err := tx.Error; err != nil {
		return 0, err
	}

	err := tx.Where("tenant_id = ? AND leaf_hash = ?", tenantID, leafHash).First(&leaf).Error
	if err == nil {
		_ = tx.Rollback()
		return leaf.LeafIndex, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		_ = tx.Rollback()
		return 0, err
	}

	var maxIndex int64
	if err := tx.Model(&TransparencyLeafModel{}).
		Where("tenant_id = ?", tenantID).
		Select("COALESCE(MAX(leaf_index), -1)").
		Scan(&maxIndex).Error; err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	leafIndex := maxIndex + 1
	newLeaf := TransparencyLeafModel{
		TenantID:         tenantID,
		LeafIndex:        leafIndex,
		LeafHash:         copyBytes(leafHash),
		SignedManifestID: signedManifestID,
		CreatedAt:        time.Now().UTC(),
	}
	if err := tx.Create(&newLeaf).Error; err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	return leafIndex, nil
}

func (r *TransparencyLogRepository) GetLeafIndex(ctx context.Context, tenantID string, leafHash []byte) (int64, error) {
	if r.db == nil {
		return 0, errDBUnavailable
	}
	var leaf TransparencyLeafModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND leaf_hash = ?", tenantID, leafHash).
		First(&leaf).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, domain.ErrNotFound
		}
		return 0, err
	}
	return leaf.LeafIndex, nil
}

func (r *TransparencyLogRepository) ListLeafHashes(ctx context.Context, tenantID string, upTo int64) ([][]byte, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	query := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("leaf_index ASC")
	if upTo > 0 {
		query = query.Where("leaf_index < ?", upTo)
	}

	var leaves []TransparencyLeafModel
	if err := query.Find(&leaves).Error; err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(leaves))
	for _, leaf := range leaves {
		out = append(out, copyBytes(leaf.LeafHash))
	}
	return out, nil
}

func (r *TransparencyLogRepository) StoreSTH(ctx context.Context, sth domain.TreeHead) error {
	if r.db == nil {
		return errDBUnavailable
	}
	model := TreeHeadModel{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  copyBytes(sth.RootHash),
		IssuedAt:  sth.IssuedAt,
		Signature: copyBytes(sth.Signature),
	}
	return r.db.WithContext(ctx).Create(&model).Error
}

func (r *TransparencyLogRepository) GetLatestSTH(ctx context.Context, tenantID string) (*domain.TreeHead, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var model TreeHeadModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("tree_size DESC").
		First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &domain.TreeHead{
		TenantID:  model.TenantID,
		TreeSize:  model.TreeSize,
		RootHash:  copyBytes(model.RootHash),
		IssuedAt:  model.IssuedAt,
		Signature: copyBytes(model.Signature),
	}, nil
}

func (r *TransparencyLogRepository) GetSTHBySize(ctx context.Context, tenantID string, treeSize int64) (*domain.TreeHead, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var model TreeHeadModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND tree_size = ?", tenantID, treeSize).
		First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &domain.TreeHead{
		TenantID:  model.TenantID,
		TreeSize:  model.TreeSize,
		RootHash:  copyBytes(model.RootHash),
		IssuedAt:  model.IssuedAt,
		Signature: copyBytes(model.Signature),
	}, nil
}
