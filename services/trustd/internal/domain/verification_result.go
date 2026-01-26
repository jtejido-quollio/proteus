package domain

type VerificationResult struct {
	SignatureValid      bool              `json:"signature_valid"`
	KeyStatus           string            `json:"key_status"`
	RevocationCheckedAt string            `json:"revocation_checked_at"`
	LogIncluded         bool              `json:"log_included"`
	SubjectHash         Hash              `json:"subject_hash"`
	ManifestID          string            `json:"manifest_id"`
	TenantID            string            `json:"tenant_id"`

	STH            *STH              `json:"sth,omitempty"`
	InclusionProof *InclusionProof   `json:"inclusion_proof,omitempty"`
	Consistency    *ConsistencyProof `json:"consistency_proof,omitempty"`

	Derivation      DerivationReceipt `json:"derivation,omitempty"`
	Policy          PolicyReceipt     `json:"policy,omitempty"`
	Decision        DecisionReceipt   `json:"decision,omitempty"`
	Replay          ReplayReceipt     `json:"replay,omitempty"`
	RevocationEpoch int64             `json:"revocation_epoch,omitempty"`
}
