package crypto

import (
	"encoding/hex"
	"time"

	"proteus/internal/domain"
)

func (s *Service) CanonicalizeSTH(sth domain.TreeHead) ([]byte, error) {
	payload := sthPayload{
		TenantID: sth.TenantID,
		TreeSize: sth.TreeSize,
		RootHash: hex.EncodeToString(sth.RootHash),
		IssuedAt: sth.IssuedAt.UTC().Format(time.RFC3339),
	}
	return CanonicalizeAny(payload)
}

func (s *Service) VerifySTHSignature(sth domain.TreeHead, signatureB64 string, pubKey []byte) error {
	canonical, err := s.CanonicalizeSTH(sth)
	if err != nil {
		return err
	}
	return s.VerifySignature(canonical, domain.Signature{Alg: "ed25519", Value: signatureB64}, pubKey)
}

type sthPayload struct {
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
	RootHash string `json:"root_hash"`
	IssuedAt string `json:"issued_at"`
}
