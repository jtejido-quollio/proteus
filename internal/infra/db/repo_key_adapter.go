package db

import (
	"context"

	"proteus/internal/domain"
)

type KeyRepository struct {
	signing    *SigningKeyRepository
	revocation *RevocationRepository
}

func NewKeyRepository(signing *SigningKeyRepository, revocation *RevocationRepository) *KeyRepository {
	return &KeyRepository{
		signing:    signing,
		revocation: revocation,
	}
}

func (r *KeyRepository) GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error) {
	if r.signing == nil {
		return nil, errDBUnavailable
	}
	return r.signing.GetByKID(ctx, tenantID, kid)
}

func (r *KeyRepository) IsRevoked(ctx context.Context, tenantID, kid string) (bool, error) {
	if r.revocation == nil {
		return false, errDBUnavailable
	}
	return r.revocation.IsRevoked(ctx, tenantID, kid)
}
