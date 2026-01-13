package capture

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
	"proteus/internal/infra/merkle"
)

type Proof struct {
	STH          domain.STH
	STHSignature string
	Inclusion    domain.InclusionProof
}

type VerifyOptions struct {
	PublicKey         ed25519.PublicKey
	LogPublicKey      ed25519.PublicKey
	Artifact          []byte
	ArtifactMediaType string
	Proof             *Proof
	RequireProof      bool
}

type VerifyResult struct {
	SignatureValid    bool
	ArtifactHashValid *bool
	LogIncluded       bool
	SubjectHash       domain.Hash
	ManifestID        string
	TenantID          string
	STH               *domain.STH
	InclusionProof    *domain.InclusionProof
}

func VerifyEnvelope(envelope domain.SignedManifestEnvelope, opts VerifyOptions) (VerifyResult, error) {
	if err := ValidateManifest(envelope.Manifest); err != nil {
		return VerifyResult{}, err
	}
	if envelope.Signature.KID == "" || envelope.Signature.Value == "" {
		return VerifyResult{}, domain.ErrInvalidManifest
	}
	if envelope.Signature.Alg != "ed25519" {
		return VerifyResult{}, domain.ErrInvalidManifest
	}
	if len(opts.PublicKey) != ed25519.PublicKeySize {
		return VerifyResult{}, errors.New("signing public key is required")
	}

	service := &cryptoinfra.Service{}
	canonical, err := service.CanonicalizeManifest(envelope.Manifest)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := service.VerifySignature(canonical, envelope.Signature, opts.PublicKey); err != nil {
		return VerifyResult{}, domain.ErrSignatureInvalid
	}

	result := VerifyResult{
		SignatureValid: true,
		LogIncluded:    false,
		SubjectHash:    envelope.Manifest.Subject.Hash,
		ManifestID:     envelope.Manifest.ManifestID,
		TenantID:       envelope.Manifest.TenantID,
	}

	if len(opts.Artifact) > 0 {
		mediaType := opts.ArtifactMediaType
		if mediaType == "" {
			mediaType = envelope.Manifest.Subject.MediaType
		}
		alg, digest, err := service.CanonicalizeAndHashArtifact(mediaType, opts.Artifact)
		if err != nil {
			return VerifyResult{}, err
		}
		if alg != envelope.Manifest.Subject.Hash.Alg || !stringsEqualFoldHex(digest, envelope.Manifest.Subject.Hash.Value) {
			return VerifyResult{}, domain.ErrArtifactHashMismatch
		}
		valid := true
		result.ArtifactHashValid = &valid
	}

	if opts.Proof == nil {
		if opts.RequireProof {
			return VerifyResult{}, domain.ErrProofRequired
		}
		return result, nil
	}

	if len(opts.LogPublicKey) != ed25519.PublicKeySize {
		return VerifyResult{}, domain.ErrSTHInvalid
	}
	if opts.Proof.STHSignature == "" {
		return VerifyResult{}, domain.ErrSTHInvalid
	}
	if err := service.VerifySTHSignature(opts.Proof.STH, opts.Proof.STHSignature, opts.LogPublicKey); err != nil {
		return VerifyResult{}, domain.ErrSTHInvalid
	}
	if opts.Proof.STH.TenantID != "" && opts.Proof.STH.TenantID != envelope.Manifest.TenantID {
		return VerifyResult{}, domain.ErrSTHInvalid
	}
	if opts.Proof.Inclusion.TenantID != "" && opts.Proof.Inclusion.TenantID != envelope.Manifest.TenantID {
		return VerifyResult{}, domain.ErrLogProofInvalid
	}
	if opts.Proof.Inclusion.STHTreeSize != opts.Proof.STH.TreeSize {
		return VerifyResult{}, domain.ErrLogProofInvalid
	}
	if !bytes.Equal(opts.Proof.Inclusion.STHRootHash, opts.Proof.STH.RootHash) {
		return VerifyResult{}, domain.ErrLogProofInvalid
	}

	leafHash, err := service.ComputeLeafHash(envelope)
	if err != nil {
		return VerifyResult{}, err
	}
	ok, err := (&merkle.Service{}).VerifyInclusionProof(
		leafHash,
		opts.Proof.Inclusion.LeafIndex,
		opts.Proof.Inclusion.STHTreeSize,
		opts.Proof.Inclusion.Path,
		opts.Proof.Inclusion.STHRootHash,
	)
	if err != nil || !ok {
		return VerifyResult{}, domain.ErrLogProofInvalid
	}

	result.LogIncluded = true
	result.STH = &opts.Proof.STH
	result.InclusionProof = &opts.Proof.Inclusion
	return result, nil
}

func stringsEqualFoldHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ra := a[i]
		rb := b[i]
		if ra == rb {
			continue
		}
		if ra >= 'A' && ra <= 'F' {
			ra = ra - 'A' + 'a'
		}
		if rb >= 'A' && rb <= 'F' {
			rb = rb - 'A' + 'a'
		}
		if ra != rb {
			return false
		}
	}
	return true
}
