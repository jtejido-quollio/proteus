package soft

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"proteus/internal/domain"
)

type RotationManager struct {
	keys *Manager
}

func NewRotationManager(keys *Manager) *RotationManager {
	return &RotationManager{keys: keys}
}

func (r *RotationManager) Rotate(_ context.Context, tenantID string, purpose domain.KeyPurpose) (domain.SigningKey, error) {
	if tenantID == "" {
		return domain.SigningKey{}, errors.New("tenant_id is required")
	}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return domain.SigningKey{}, err
	}
	kid := keyIDFromPublicKey(pubKey)
	if r.keys != nil {
		if r.keys.keys == nil {
			r.keys.keys = make(map[string]ed25519.PrivateKey)
		}
		r.keys.keys[keyRefKey(domain.KeyRef{
			TenantID: tenantID,
			Purpose:  purpose,
			KID:      kid,
		})] = privKey
	}
	return domain.SigningKey{
		TenantID:  tenantID,
		KID:       kid,
		Purpose:   purpose,
		Alg:       "ed25519",
		PublicKey: pubKey,
		Status:    domain.KeyStatusActive,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func keyIDFromPublicKey(pubKey ed25519.PublicKey) string {
	sum := sha256.Sum256(pubKey)
	return hex.EncodeToString(sum[:])
}
