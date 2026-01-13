package usecase

import (
	"context"
	"errors"

	"proteus/internal/domain"
)

type RecordSignedManifestRequest struct {
	Envelope domain.SignedManifestEnvelope
}

type RecordSignedManifestResponse struct {
	ManifestID string
	LeafHash   []byte
	LeafIndex  int64
	STH        *domain.STH
	Inclusion  *domain.InclusionProof
	// InclusionProof included by default in Phase 1 implementation.
}

type RecordSignedManifest struct {
	Tenants TenantRepository
	Keys    KeyRepository
	Manif   ManifestRepository
	Log     TenantLog
	Crypto  CryptoService
	Provenance ProvenanceRepository
}

func (uc *RecordSignedManifest) Execute(ctx context.Context, req RecordSignedManifestRequest) (*RecordSignedManifestResponse, error) {
	env := req.Envelope
	if err := validateManifest(env.Manifest); err != nil {
		return nil, err
	}
	if env.Signature.KID == "" || env.Signature.Value == "" {
		return nil, domain.ErrInvalidManifest
	}
	if env.Signature.Alg != "ed25519" {
		return nil, domain.ErrInvalidManifest
	}

	key, err := uc.Keys.GetByKID(ctx, env.Manifest.TenantID, env.Signature.KID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrKeyUnknown
		}
		return nil, err
	}

	revoked, err := uc.Keys.IsRevoked(ctx, env.Manifest.TenantID, env.Signature.KID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, domain.ErrKeyRevoked
	}

	canonical, err := uc.Crypto.CanonicalizeManifest(env.Manifest)
	if err != nil {
		return nil, err
	}
	if err := uc.Crypto.VerifySignature(canonical, env.Signature, key.PublicKey); err != nil {
		return nil, domain.ErrSignatureInvalid
	}

	leafHash, err := uc.Crypto.ComputeLeafHash(env)
	if err != nil {
		return nil, err
	}

	manifestID, signedManifestID, err := uc.Manif.UpsertManifestAndEnvelope(ctx, env)
	if err != nil {
		return nil, err
	}

	if err := uc.persistProvenance(ctx, env, manifestID); err != nil {
		return nil, err
	}

	leafIndex, sth, inclusion, err := uc.Log.AppendLeaf(ctx, env.Manifest.TenantID, signedManifestID, leafHash)
	if err != nil {
		return nil, err
	}

	return &RecordSignedManifestResponse{
		ManifestID: manifestID,
		LeafHash:   leafHash,
		LeafIndex:  leafIndex,
		STH:        &sth,
		Inclusion:  &inclusion,
	}, nil
}

func (uc *RecordSignedManifest) persistProvenance(ctx context.Context, env domain.SignedManifestEnvelope, manifestID string) error {
	if uc.Provenance == nil {
		return nil
	}
	createdAt := env.Manifest.Time.SubmittedAt
	subject := domain.Artifact{
		TenantID:  env.Manifest.TenantID,
		Hash:      env.Manifest.Subject.Hash,
		MediaType: env.Manifest.Subject.MediaType,
		URI:       env.Manifest.Subject.URI,
		CreatedAt: createdAt,
	}
	subjectID, err := uc.Provenance.UpsertArtifact(ctx, env.Manifest.TenantID, subject)
	if err != nil {
		return err
	}
	if err := uc.Provenance.AddEdge(ctx, domain.ProvenanceEdge{
		TenantID:   env.Manifest.TenantID,
		ManifestID: manifestID,
		Type:       domain.ProvenanceEdgeGenerated,
		ArtifactID: subjectID,
		CreatedAt:  createdAt,
	}); err != nil {
		return err
	}

	inputs := sortedInputs(env.Manifest.Inputs)
	for _, input := range inputs {
		if input.Hash.Alg == "" || input.Hash.Value == "" {
			continue
		}
		artifact := domain.Artifact{
			TenantID:  env.Manifest.TenantID,
			Hash:      input.Hash,
			MediaType: input.MediaType,
			URI:       input.URI,
			CreatedAt: createdAt,
		}
		artifactID, err := uc.Provenance.UpsertArtifact(ctx, env.Manifest.TenantID, artifact)
		if err != nil {
			return err
		}
		if err := uc.Provenance.AddEdge(ctx, domain.ProvenanceEdge{
			TenantID:   env.Manifest.TenantID,
			ManifestID: manifestID,
			Type:       domain.ProvenanceEdgeUsed,
			ArtifactID: artifactID,
			CreatedAt:  createdAt,
		}); err != nil {
			return err
		}
	}

	if env.Signature.KID != "" {
		if err := uc.Provenance.AddEdge(ctx, domain.ProvenanceEdge{
			TenantID:   env.Manifest.TenantID,
			ManifestID: manifestID,
			Type:       domain.ProvenanceEdgeSignedBy,
			KID:        env.Signature.KID,
			CreatedAt:  createdAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

func validateManifest(manifest domain.Manifest) error {
	if manifest.Schema == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.ManifestID == "" || manifest.TenantID == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.Subject.Type == "" || manifest.Subject.MediaType == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.Subject.Hash.Alg != "sha256" || manifest.Subject.Hash.Value == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.Actor.Type == "" || manifest.Actor.ID == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.Tool.Name == "" || manifest.Tool.Version == "" {
		return domain.ErrInvalidManifest
	}
	if manifest.Time.CreatedAt.IsZero() || manifest.Time.SubmittedAt.IsZero() {
		return domain.ErrInvalidManifest
	}
	return nil
}
