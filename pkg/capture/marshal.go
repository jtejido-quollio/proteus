package capture

import (
	"encoding/json"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
)

type envelopePayload struct {
	Manifest  json.RawMessage  `json:"manifest"`
	Signature domain.Signature `json:"signature"`
	CertChain []string         `json:"cert_chain,omitempty"`
}

func MarshalManifest(manifest domain.Manifest) ([]byte, error) {
	service := &cryptoinfra.Service{}
	return service.CanonicalizeManifest(manifest)
}

func MarshalEnvelope(envelope domain.SignedManifestEnvelope) ([]byte, error) {
	service := &cryptoinfra.Service{}
	manifest, err := service.CanonicalizeManifest(envelope.Manifest)
	if err != nil {
		return nil, err
	}
	payload := envelopePayload{
		Manifest:  json.RawMessage(manifest),
		Signature: envelope.Signature,
		CertChain: envelope.CertChain,
	}
	return cryptoinfra.CanonicalizeAny(payload)
}

func MarshalHash(hash domain.Hash) ([]byte, error) {
	return cryptoinfra.CanonicalizeAny(hash)
}
