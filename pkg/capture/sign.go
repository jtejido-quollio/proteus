package capture

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
)

func SignManifest(manifest domain.Manifest, kid string, privateKey ed25519.PrivateKey) (domain.Signature, []byte, error) {
	if kid == "" {
		return domain.Signature{}, nil, errors.New("kid is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return domain.Signature{}, nil, errors.New("invalid ed25519 private key")
	}
	service := &cryptoinfra.Service{}
	canonical, err := service.CanonicalizeManifest(manifest)
	if err != nil {
		return domain.Signature{}, nil, err
	}
	sig := ed25519.Sign(privateKey, canonical)
	return domain.Signature{
		Alg:   "ed25519",
		KID:   kid,
		Value: base64.StdEncoding.EncodeToString(sig),
	}, canonical, nil
}

func BuildEnvelope(manifest domain.Manifest, signature domain.Signature, certChain []string) domain.SignedManifestEnvelope {
	return domain.SignedManifestEnvelope{
		Manifest:  manifest,
		Signature: signature,
		CertChain: certChain,
	}
}
