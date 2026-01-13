package db

import (
	"context"
	"errors"

	"proteus/internal/domain"

	"gorm.io/gorm"
)

type TenantRepository struct {
	db *gorm.DB
}

func NewTenantRepository(db *gorm.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

func (r *TenantRepository) Create(ctx context.Context, tenant domain.Tenant) error {
	if r.db == nil {
		return errDBUnavailable
	}
	model := TenantModel{
		ID:        tenant.ID,
		Name:      tenant.Name,
		CreatedAt: tenant.CreatedAt,
	}
	return r.db.WithContext(ctx).Create(&model).Error
}

func (r *TenantRepository) GetByID(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var model TenantModel
	err := r.db.WithContext(ctx).First(&model, "id = ?", tenantID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &domain.Tenant{
		ID:        model.ID,
		Name:      model.Name,
		CreatedAt: model.CreatedAt,
	}, nil
}
