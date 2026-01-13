package domain

type PolicyInput struct {
	Envelope     SignedManifestEnvelope `json:"envelope"`
	Verification PolicyVerification     `json:"verification"`
	Options      *PolicyOptions         `json:"options,omitempty"`
	Derivation   DerivationReceipt      `json:"derivation,omitempty"`
}

type PolicyVerification struct {
	SignatureValid    bool   `json:"signature_valid"`
	KeyStatus         string `json:"key_status"`
	LogIncluded       bool   `json:"log_included"`
	ArtifactHashValid *bool  `json:"artifact_hash_valid,omitempty"`
}

type PolicyOptions struct {
	RequireProof bool `json:"require_proof,omitempty"`
}

type PolicyDeny struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

type PolicyResult struct {
	Allow bool         `json:"allow"`
	Deny  []PolicyDeny `json:"deny,omitempty"`
}

type PolicyEvaluation struct {
	BundleID   string       `json:"bundle_id,omitempty"`
	BundleHash string       `json:"bundle_hash"`
	Result     PolicyResult `json:"result"`
}
