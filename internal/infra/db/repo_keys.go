package db

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
)

type SigningKeyRepository struct {
	db *gorm.DB
}

func NewSigningKeyRepository(db *gorm.DB) *SigningKeyRepository {
	return &SigningKeyRepository{db: db}
}

func (r *SigningKeyRepository) GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var model SigningKeyModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND kid = ?", tenantID, kid).
		First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return signingKeyFromModel(model), nil
}

func (r *SigningKeyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.SigningKey, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var models []SigningKeyModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at ASC").
		Find(&models).Error
	if err != nil {
		return nil, err
	}
	out := make([]domain.SigningKey, 0, len(models))
	for _, model := range models {
		out = append(out, *signingKeyFromModel(model))
	}
	return out, nil
}

func (r *SigningKeyRepository) Create(ctx context.Context, key domain.SigningKey) error {
	if r.db == nil {
		return errDBUnavailable
	}
	keyID := key.ID
	if keyID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		keyID = id
	}
	status := key.Status
	if status == "" {
		status = domain.KeyStatusActive
	}
	createdAt := key.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	model := SigningKeyModel{
		ID:        keyID,
		TenantID:  key.TenantID,
		KID:       key.KID,
		Alg:       key.Alg,
		PublicKey: copyBytes(key.PublicKey),
		Status:    string(status),
		NotBefore: key.NotBefore,
		NotAfter:  key.NotAfter,
		CreatedAt: createdAt,
	}
	return r.db.WithContext(ctx).Create(&model).Error
}

type LogKeyRepository struct {
	db *gorm.DB
}

func NewLogKeyRepository(db *gorm.DB) *LogKeyRepository {
	return &LogKeyRepository{db: db}
}

func (r *LogKeyRepository) GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var model SigningKeyModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND status = ?", tenantID, string(domain.KeyStatusActive)).
		Order("created_at DESC").
		First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return signingKeyFromModel(model), nil
}

func (r *LogKeyRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.SigningKey, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var models []SigningKeyModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at ASC").
		Find(&models).Error
	if err != nil {
		return nil, err
	}
	out := make([]domain.SigningKey, 0, len(models))
	for _, model := range models {
		out = append(out, *signingKeyFromModel(model))
	}
	return out, nil
}

func (r *LogKeyRepository) Create(ctx context.Context, key domain.SigningKey) error {
	if r.db == nil {
		return errDBUnavailable
	}
	keyID := key.ID
	if keyID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		keyID = id
	}
	status := key.Status
	if status == "" {
		status = domain.KeyStatusActive
	}
	createdAt := key.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	model := SigningKeyModel{
		ID:        keyID,
		TenantID:  key.TenantID,
		KID:       key.KID,
		Alg:       key.Alg,
		PublicKey: copyBytes(key.PublicKey),
		Status:    string(status),
		NotBefore: key.NotBefore,
		NotAfter:  key.NotAfter,
		CreatedAt: createdAt,
	}
	return r.db.WithContext(ctx).Create(&model).Error
}

func signingKeyFromModel(model SigningKeyModel) *domain.SigningKey {
	return &domain.SigningKey{
		ID:        model.ID,
		TenantID:  model.TenantID,
		KID:       model.KID,
		Alg:       model.Alg,
		PublicKey: copyBytes(model.PublicKey),
		Status:    domain.KeyStatus(model.Status),
		NotBefore: model.NotBefore,
		NotAfter:  model.NotAfter,
		CreatedAt: model.CreatedAt,
	}
}
