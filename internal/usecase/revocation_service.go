package usecase

import (
	"context"
	"errors"

	"proteus/internal/domain"
)

type RevocationService struct {
	Revocations RevocationRepository
	Epochs      RevocationEpochRepository
}

func NewRevocationService(revocations RevocationRepository, epochs RevocationEpochRepository) *RevocationService {
	return &RevocationService{
		Revocations: revocations,
		Epochs:      epochs,
	}
}

func (s *RevocationService) Revoke(ctx context.Context, rev domain.Revocation) (int64, error) {
	if s == nil {
		return 0, errors.New("revocation service is nil")
	}
	if s.Revocations == nil {
		return 0, errors.New("revocation repository is required")
	}
	if err := s.Revocations.Revoke(ctx, rev); err != nil {
		return 0, err
	}
	if s.Epochs == nil {
		return 0, nil
	}
	epoch, err := s.Epochs.BumpEpoch(ctx, rev.TenantID)
	if err != nil {
		return 0, err
	}
	return epoch, nil
}
