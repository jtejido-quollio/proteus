package db

import (
	"context"
	"errors"

	"proteus/internal/domain"
)

type LogKeyFallbackRepository struct {
	logRepo     *LogKeyRepository
	signingRepo *SigningKeyRepository
}

func NewLogKeyFallbackRepository(logRepo *LogKeyRepository, signingRepo *SigningKeyRepository) *LogKeyFallbackRepository {
	return &LogKeyFallbackRepository{
		logRepo:     logRepo,
		signingRepo: signingRepo,
	}
}

func (r *LogKeyFallbackRepository) GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error) {
	if r == nil {
		return nil, errDBUnavailable
	}
	if r.logRepo != nil {
		key, err := r.logRepo.GetActive(ctx, tenantID)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
	}
	if r.signingRepo != nil {
		return r.signingRepo.GetActive(ctx, tenantID)
	}
	return nil, errDBUnavailable
}

func (r *LogKeyFallbackRepository) ListByTenant(ctx context.Context, tenantID string) ([]domain.SigningKey, error) {
	if r == nil {
		return nil, errDBUnavailable
	}
	if r.logRepo != nil {
		keys, err := r.logRepo.ListByTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			return keys, nil
		}
	}
	if r.signingRepo != nil {
		return r.signingRepo.ListByTenant(ctx, tenantID)
	}
	return nil, errDBUnavailable
}

func (r *LogKeyFallbackRepository) Create(ctx context.Context, key domain.SigningKey) error {
	if r == nil || r.logRepo == nil {
		return errDBUnavailable
	}
	return r.logRepo.Create(ctx, key)
}
