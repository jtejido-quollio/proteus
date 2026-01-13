package domain

import "time"

type Hash struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type Subject struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Hash      Hash   `json:"hash"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	URI       string `json:"uri,omitempty"`
}

type Actor struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Display string `json:"display,omitempty"`
}

type Tool struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type ManifestTime struct {
	CreatedAt   time.Time `json:"created_at"`
	SubmittedAt time.Time `json:"submitted_at"`
}

type InputArtifact struct {
	MediaType string `json:"media_type"`
	Hash      Hash   `json:"hash"`
	URI       string `json:"uri,omitempty"`
}

type Manifest struct {
	Schema     string                 `json:"schema"`
	ManifestID string                 `json:"manifest_id"`
	TenantID   string                 `json:"tenant_id"`
	Subject    Subject                `json:"subject"`
	Actor      Actor                  `json:"actor"`
	Tool       Tool                   `json:"tool"`
	Time       ManifestTime            `json:"time"`
	Inputs     []InputArtifact         `json:"inputs,omitempty"`
	Claims     map[string]any          `json:"claims,omitempty"`
}

type Signature struct {
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Value string `json:"value"` // base64
}

type SignedManifestEnvelope struct {
	Manifest  Manifest   `json:"manifest"`
	Signature Signature  `json:"signature"`
	CertChain []string   `json:"cert_chain,omitempty"`
}
