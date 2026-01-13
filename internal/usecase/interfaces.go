package usecase

import (
	"context"

	"proteus/internal/domain"
)

type TenantRepository interface {
	GetByID(ctx context.Context, tenantID string) (*domain.Tenant, error)
	Create(ctx context.Context, t domain.Tenant) error
}

type KeyRepository interface {
	GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error)
	IsRevoked(ctx context.Context, tenantID, kid string) (bool, error)
}

type ManifestRepository interface {
	UpsertManifestAndEnvelope(ctx context.Context, env domain.SignedManifestEnvelope) (manifestID string, signedManifestID string, err error)
}

type ManifestReader interface {
	GetEnvelopeByManifestID(ctx context.Context, tenantID, manifestID string) (*domain.SignedManifestEnvelope, error)
}

type ProvenanceRepository interface {
	UpsertArtifact(ctx context.Context, tenantID string, artifact domain.Artifact) (string, error)
	AddEdge(ctx context.Context, edge domain.ProvenanceEdge) error
	ListGeneratedManifestIDs(ctx context.Context, tenantID string, hash domain.Hash) ([]string, error)
}

type TenantLog interface {
	AppendLeaf(ctx context.Context, tenantID string, signedManifestID string, leafHash []byte) (leafIndex int64, sth domain.STH, inclusion domain.InclusionProof, err error)
	GetInclusionProof(ctx context.Context, tenantID string, leafHash []byte) (leafIndex int64, sth domain.STH, inclusion domain.InclusionProof, err error)
	GetConsistencyProof(ctx context.Context, tenantID string, fromSize, toSize int64) (proof domain.ConsistencyProof, err error)
	GetLatestSTH(ctx context.Context, tenantID string) (sth domain.STH, err error)
}

type LogKeyRepository interface {
	GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error)
}

type CryptoService interface {
	CanonicalizeAndHashArtifact(mediaType string, bytes []byte) (alg string, hexDigest string, err error)
	CanonicalizeManifest(manifest domain.Manifest) ([]byte, error)
	CanonicalizeAny(payload any) ([]byte, error)
	VerifySignature(manifestCanonical []byte, sig domain.Signature, pubKey []byte) error
	ComputeLeafHash(env domain.SignedManifestEnvelope) ([]byte, error)
	VerifySTHSignature(sth domain.TreeHead, signatureB64 string, pubKey []byte) error
}

type MerkleService interface {
	VerifyInclusionProof(leafHash []byte, leafIndex int64, treeSize int64, path [][]byte, expectedRoot []byte) (bool, error)
}

type PolicyEngine interface {
	Evaluate(ctx context.Context, input domain.PolicyInput) (domain.PolicyEvaluation, error)
}

type DerivationService interface {
	Verify(ctx context.Context, tenantID, manifestID string) (domain.DerivationSummary, error)
}

type DecisionEngine interface {
	Evaluate(input DecisionInput) (DecisionResult, error)
}
