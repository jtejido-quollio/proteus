package domain

type VerificationReceipt struct {
	SignatureValid      bool              `json:"signature_valid"`
	KeyStatus           string            `json:"key_status"`
	RevocationCheckedAt string            `json:"revocation_checked_at"`
	LogIncluded         bool              `json:"log_included"`
	SubjectHash         Hash              `json:"subject_hash"`
	ManifestID          string            `json:"manifest_id"`
	TenantID            string            `json:"tenant_id"`
	STH                *STH              `json:"sth,omitempty"`
	InclusionProof      *InclusionProof   `json:"inclusion_proof,omitempty"`
	Consistency         *ConsistencyProof `json:"consistency_proof,omitempty"`
}

type DerivationReceipt map[string]any

type PolicyReceipt map[string]any

type DecisionReceipt map[string]any

type ReplayReceipt map[string]any
