package anchor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
)

type Payload struct {
	TenantID        string
	TreeSize        int64
	RootHashBase64  string
	SignatureBase64 string
	CanonicalJSON   []byte
	HashHex         string
}

func BuildPayload(tenantID string, sth domain.STH) (Payload, error) {
	if tenantID == "" {
		return Payload{}, errors.New("tenant_id is required")
	}
	if len(sth.RootHash) == 0 {
		return Payload{}, errors.New("sth.root_hash is required")
	}
	signatureB64 := base64.StdEncoding.EncodeToString(sth.Signature)
	payload := map[string]any{
		"v":                    "proteus_anchor_v0",
		"tenant_id":            tenantID,
		"tree_size":            sth.TreeSize,
		"root_hash_base64":     base64.StdEncoding.EncodeToString(sth.RootHash),
		"sth_signature_base64": signatureB64,
	}
	canonical, err := cryptoinfra.CanonicalizeAny(payload)
	if err != nil {
		return Payload{}, err
	}
	sum := sha256.Sum256(canonical)
	return Payload{
		TenantID:        tenantID,
		TreeSize:        sth.TreeSize,
		RootHashBase64:  payload["root_hash_base64"].(string),
		SignatureBase64: signatureB64,
		CanonicalJSON:   canonical,
		HashHex:         hex.EncodeToString(sum[:]),
	}, nil
}
