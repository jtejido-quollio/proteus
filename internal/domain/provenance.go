package domain

import "time"

type Artifact struct {
	TenantID  string
	Hash      Hash
	MediaType string
	URI       string
	CreatedAt time.Time
}

type ProvenanceEdgeType string

const (
	ProvenanceEdgeUsed      ProvenanceEdgeType = "USED"
	ProvenanceEdgeGenerated ProvenanceEdgeType = "GENERATED"
	ProvenanceEdgeSignedBy  ProvenanceEdgeType = "SIGNED_BY"
)

type ProvenanceEdge struct {
	TenantID   string
	ManifestID string
	Type       ProvenanceEdgeType
	ArtifactID string
	KID        string
	CreatedAt  time.Time
}

type DerivationSeverity string

const (
	DerivationSeverityNone  DerivationSeverity = "none"
	DerivationSeverityError DerivationSeverity = "error"
)

type DerivationFailure struct {
	Code         string `json:"code"`
	Message      string `json:"message,omitempty"`
	ManifestID   string `json:"manifest_id,omitempty"`
	ArtifactHash *Hash  `json:"artifact_hash,omitempty"`
}

const (
	DerivationFailureManifestNotFound    = "MANIFEST_NOT_FOUND"
	DerivationFailureInputMissing        = "INPUT_MISSING"
	DerivationFailureMultipleGenerators  = "MULTIPLE_GENERATORS"
	DerivationFailureCycleDetected       = "CYCLE_DETECTED"
	DerivationFailureInputInvalid        = "INPUT_INVALID"
	DerivationFailureToolMetadataMissing = "TOOL_METADATA_MISSING"
	DerivationFailureTimeParadox         = "TIME_PARADOX"
	DerivationFailureSignerRevoked       = "SIGNER_REVOKED"
	DerivationFailureArtifactMissing     = "ARTIFACT_MISSING"
)

type DerivationSummary struct {
	Complete bool                `json:"complete"`
	Depth    int                 `json:"depth"`
	Failures []DerivationFailure `json:"failures,omitempty"`
	Severity DerivationSeverity  `json:"severity"`
}
