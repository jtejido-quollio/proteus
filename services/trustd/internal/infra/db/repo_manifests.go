package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"proteus/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ManifestRepository struct {
	db *gorm.DB
}

func NewManifestRepository(db *gorm.DB) *ManifestRepository {
	return &ManifestRepository{db: db}
}

func (r *ManifestRepository) UpsertManifestAndEnvelope(ctx context.Context, env domain.SignedManifestEnvelope) (string, string, error) {
	if r.db == nil {
		return "", "", errDBUnavailable
	}
	manifestID := env.Manifest.ManifestID
	if manifestID == "" {
		return "", "", errors.New("manifest_id is required")
	}
	if env.Manifest.TenantID == "" {
		return "", "", errors.New("tenant_id is required")
	}

	manifestJSON, err := json.Marshal(env.Manifest)
	if err != nil {
		return "", "", err
	}

	manifestModel := ManifestModel{
		ID:               manifestID,
		TenantID:         env.Manifest.TenantID,
		SubjectHashAlg:   env.Manifest.Subject.Hash.Alg,
		SubjectHashValue: env.Manifest.Subject.Hash.Value,
		SubjectMediaType: env.Manifest.Subject.MediaType,
		ManifestJSON:     manifestJSON,
		CreatedAt:        env.Manifest.Time.CreatedAt,
	}

	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return "", "", err
	}

	signedManifestID, err := newUUID()
	if err != nil {
		return "", "", err
	}

	signedModel := SignedManifestModel{
		ID:         signedManifestID,
		TenantID:   env.Manifest.TenantID,
		ManifestID: manifestID,
		KID:        env.Signature.KID,
		SigAlg:     env.Signature.Alg,
		Signature:  sigBytes,
		ReceivedAt: time.Now().UTC(),
	}

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&manifestModel).Error; err != nil {
			return err
		}
		if err := tx.Create(&signedModel).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}

	return manifestID, signedManifestID, nil
}

func (r *ManifestRepository) GetEnvelopeByManifestID(ctx context.Context, tenantID, manifestID string) (*domain.SignedManifestEnvelope, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var signed SignedManifestModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND manifest_id = ?", tenantID, manifestID).
		Order("received_at DESC").
		First(&signed).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return r.getEnvelopeBySignedManifest(ctx, signed)
}

func (r *ManifestRepository) GetEnvelopeByLeafHash(ctx context.Context, tenantID string, leafHash []byte) (*domain.SignedManifestEnvelope, error) {
	if r.db == nil {
		return nil, errDBUnavailable
	}
	var leaf TransparencyLeafModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND leaf_hash = ?", tenantID, leafHash).
		First(&leaf).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	var signed SignedManifestModel
	err = r.db.WithContext(ctx).First(&signed, "id = ?", leaf.SignedManifestID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return r.getEnvelopeBySignedManifest(ctx, signed)
}

func (r *ManifestRepository) getEnvelopeBySignedManifest(ctx context.Context, signed SignedManifestModel) (*domain.SignedManifestEnvelope, error) {
	var manifestModel ManifestModel
	err := r.db.WithContext(ctx).
		First(&manifestModel, "id = ? AND tenant_id = ?", signed.ManifestID, signed.TenantID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	var manifest domain.Manifest
	if err := json.Unmarshal(manifestModel.ManifestJSON, &manifest); err != nil {
		return nil, err
	}

	sig := domain.Signature{
		Alg:   signed.SigAlg,
		KID:   signed.KID,
		Value: base64.StdEncoding.EncodeToString(signed.Signature),
	}

	return &domain.SignedManifestEnvelope{
		Manifest:  manifest,
		Signature: sig,
	}, nil
}
