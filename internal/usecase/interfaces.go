package usecase

import (
	"context"
	"time"

	"proteus/internal/domain"
)

type TenantRepository interface {
	GetByID(ctx context.Context, tenantID string) (*domain.Tenant, error)
	Create(ctx context.Context, t domain.Tenant) error
}

type AuditEventRepository interface {
	Append(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error)
	ListByTenant(ctx context.Context, tenantID string) ([]domain.AuditEvent, error)
}

type KeyRepository interface {
	GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error)
	IsRevoked(ctx context.Context, tenantID, kid string) (bool, error)
}

type RevocationRepository interface {
	Revoke(ctx context.Context, rev domain.Revocation) error
}

type RevocationEpochRepository interface {
	GetEpoch(ctx context.Context, tenantID string) (int64, error)
	BumpEpoch(ctx context.Context, tenantID string) (int64, error)
}

type KeyRotationManager interface {
	Rotate(ctx context.Context, tenantID string, purpose domain.KeyPurpose) (domain.SigningKey, error)
}

type KeyRotationStore interface {
	GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error)
	Create(ctx context.Context, key domain.SigningKey) error
	UpdateStatus(ctx context.Context, tenantID, kid string, status domain.KeyStatus) error
	WithTx(ctx context.Context, fn func(store KeyRotationStore) error) error
}

type KeyMaterialStore interface {
	Put(ctx context.Context, material KeyMaterial) error
	Delete(ctx context.Context, ref domain.KeyRef) error
}

type KeyMaterial struct {
	Ref        domain.KeyRef
	PrivateKey []byte
	PublicKey  []byte
	Alg        string
	Status     domain.KeyStatus
	CreatedAt  time.Time
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
	GetArtifactByHash(ctx context.Context, tenantID string, hash domain.Hash) (*domain.Artifact, error)
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

type VerificationCache interface {
	Get(ctx context.Context, key string) (*domain.VerificationResult, bool, error)
	Put(ctx context.Context, key string, value domain.VerificationResult, ttl time.Duration) error
}
