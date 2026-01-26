package capture

import (
	"crypto/sha256"
	"encoding/hex"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
)

type ArtifactCapture struct {
	Hash      domain.Hash
	Canonical []byte
}

func CaptureArtifact(mediaType string, input []byte) (ArtifactCapture, error) {
	canonical, err := cryptoinfra.CanonicalizeArtifact(mediaType, input)
	if err != nil {
		return ArtifactCapture{}, err
	}
	sum := sha256.Sum256(canonical)
	return ArtifactCapture{
		Hash: domain.Hash{
			Alg:   "sha256",
			Value: hex.EncodeToString(sum[:]),
		},
		Canonical: canonical,
	}, nil
}
