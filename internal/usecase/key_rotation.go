package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"proteus/internal/domain"
)

type Clock func() time.Time

type KeyRotationService struct {
	SigningStore KeyRotationStore
	LogStore     KeyRotationStore
	Material     KeyMaterialStore
	Clock        Clock
	Interval     time.Duration
}

func NewKeyRotationService(signing KeyRotationStore, log KeyRotationStore, material KeyMaterialStore, clock Clock) *KeyRotationService {
	return &KeyRotationService{
		SigningStore: signing,
		LogStore:     log,
		Material:     material,
		Clock:        clock,
	}
}

func NewKeyRotationServiceWithInterval(signing KeyRotationStore, log KeyRotationStore, material KeyMaterialStore, clock Clock, interval time.Duration) *KeyRotationService {
	svc := NewKeyRotationService(signing, log, material, clock)
	svc.Interval = interval
	return svc
}

func (s *KeyRotationService) Rotate(ctx context.Context, tenantID string, purpose domain.KeyPurpose) (domain.SigningKey, error) {
	store := s.storeForPurpose(purpose)
	if store == nil {
		return domain.SigningKey{}, errors.New("key rotation store is required")
	}
	if s.Material == nil {
		return domain.SigningKey{}, errors.New("key material store is required")
	}
	if tenantID == "" {
		return domain.SigningKey{}, errors.New("tenant_id is required")
	}

	oldKey, err := store.GetActive(ctx, tenantID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return domain.SigningKey{}, err
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return domain.SigningKey{}, err
	}
	now := s.now().UTC()
	kid := keyIDFromPublicKey(pubKey)
	newKey := domain.SigningKey{
		TenantID:  tenantID,
		KID:       kid,
		Purpose:   purpose,
		Alg:       "ed25519",
		PublicKey: pubKey,
		Status:    domain.KeyStatusActive,
		CreatedAt: now,
	}
	ref := domain.KeyRef{
		TenantID: tenantID,
		Purpose:  purpose,
		KID:      kid,
	}
	material := KeyMaterial{
		Ref:        ref,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Alg:        "ed25519",
		Status:     domain.KeyStatusActive,
		CreatedAt:  now,
	}
	if err := s.Material.Put(ctx, material); err != nil {
		return domain.SigningKey{}, err
	}

	if err := store.WithTx(ctx, func(txStore KeyRotationStore) error {
		if err := txStore.Create(ctx, newKey); err != nil {
			return err
		}
		if oldKey != nil {
			if err := txStore.UpdateStatus(ctx, tenantID, oldKey.KID, domain.KeyStatusRetired); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = s.Material.Delete(ctx, ref)
		return domain.SigningKey{}, err
	}

	return newKey, nil
}

func (s *KeyRotationService) RotateIfDue(ctx context.Context, tenantID string, purpose domain.KeyPurpose) (bool, *domain.SigningKey, error) {
	store := s.storeForPurpose(purpose)
	if store == nil {
		return false, nil, errors.New("key rotation store is required")
	}
	if tenantID == "" {
		return false, nil, errors.New("tenant_id is required")
	}
	active, err := store.GetActive(ctx, tenantID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return false, nil, err
	}
	if active == nil {
		rotated, err := s.Rotate(ctx, tenantID, purpose)
		if err != nil {
			return false, nil, err
		}
		return true, &rotated, nil
	}
	interval := s.Interval
	if interval <= 0 {
		return false, active, nil
	}
	if active.CreatedAt.IsZero() {
		rotated, err := s.Rotate(ctx, tenantID, purpose)
		if err != nil {
			return false, nil, err
		}
		return true, &rotated, nil
	}
	if s.now().Sub(active.CreatedAt) >= interval {
		rotated, err := s.Rotate(ctx, tenantID, purpose)
		if err != nil {
			return false, nil, err
		}
		return true, &rotated, nil
	}
	return false, active, nil
}

func (s *KeyRotationService) storeForPurpose(purpose domain.KeyPurpose) KeyRotationStore {
	switch purpose {
	case domain.KeyPurposeSigning:
		return s.SigningStore
	case domain.KeyPurposeLog:
		return s.LogStore
	default:
		return nil
	}
}

func (s *KeyRotationService) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now().UTC()
}

func keyIDFromPublicKey(pubKey ed25519.PublicKey) string {
	sum := sha256.Sum256(pubKey)
	return hex.EncodeToString(sum[:])
}
