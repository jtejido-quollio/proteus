package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"proteus/internal/domain"
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) CanonicalizeManifest(manifest domain.Manifest) ([]byte, error) {
	return CanonicalizeAny(buildManifestPayload(manifest))
}

func (s *Service) CanonicalizeAny(payload any) ([]byte, error) {
	return CanonicalizeAny(payload)
}

func (s *Service) CanonicalizeAndHashArtifact(mediaType string, input []byte) (string, string, error) {
	return CanonicalizeAndHashArtifact(mediaType, input)
}

func (s *Service) VerifySignature(manifestCanonical []byte, sig domain.Signature, pubKey []byte) error {
	if sig.Alg != "" && sig.Alg != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", sig.Alg)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length: %d", len(pubKey))
	}
	if sig.Value == "" {
		return errors.New("signature value is required")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length: %d", len(sigBytes))
	}
	if !ed25519.Verify(pubKey, manifestCanonical, sigBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func (s *Service) ComputeLeafHash(env domain.SignedManifestEnvelope) ([]byte, error) {
	payload := leafPayload{
		Manifest:  buildManifestPayload(env.Manifest),
		Signature: env.Signature,
	}
	canonical, err := CanonicalizeAny(payload)
	if err != nil {
		return nil, err
	}
	return sha256Bytes(canonical), nil
}

type manifestPayload struct {
	Schema     string                  `json:"schema"`
	ManifestID string                  `json:"manifest_id"`
	TenantID   string                  `json:"tenant_id"`
	Subject    domain.Subject          `json:"subject"`
	Actor      domain.Actor            `json:"actor"`
	Tool       domain.Tool             `json:"tool"`
	Time       domain.ManifestTime     `json:"time"`
	Inputs     *[]domain.InputArtifact `json:"inputs,omitempty"`
	Claims     *map[string]any         `json:"claims,omitempty"`
}

type leafPayload struct {
	Manifest  manifestPayload  `json:"manifest"`
	Signature domain.Signature `json:"signature"`
}

func buildManifestPayload(manifest domain.Manifest) manifestPayload {
	payload := manifestPayload{
		Schema:     manifest.Schema,
		ManifestID: manifest.ManifestID,
		TenantID:   manifest.TenantID,
		Subject:    manifest.Subject,
		Actor:      manifest.Actor,
		Tool:       manifest.Tool,
		Time:       manifest.Time,
	}

	if manifest.Inputs != nil {
		inputs := manifest.Inputs
		payload.Inputs = &inputs
	}
	if manifest.Claims != nil {
		claims := manifest.Claims
		payload.Claims = &claims
	}

	return payload
}
