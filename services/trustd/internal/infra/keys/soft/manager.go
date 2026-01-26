package soft

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"proteus/internal/config"
	"proteus/internal/domain"
)

type Manager struct {
	keys map[string]ed25519.PrivateKey

	logPrivateKeyBase64      string
	logPrivateKeySeedHex     string
	signingPrivateKeyBase64  string
	signingPrivateKeySeedHex string
}

func NewManager(keys map[domain.KeyRef]ed25519.PrivateKey) *Manager {
	keyMap := make(map[string]ed25519.PrivateKey, len(keys))
	for ref, key := range keys {
		keyMap[keyRefKey(ref)] = append(ed25519.PrivateKey(nil), key...)
	}
	return &Manager{keys: keyMap}
}

func NewManagerFromConfig(cfg config.Config) *Manager {
	return &Manager{
		logPrivateKeyBase64:      cfg.LogPrivateKeyBase64,
		logPrivateKeySeedHex:     cfg.LogPrivateKeySeedHex,
		signingPrivateKeyBase64:  cfg.SigningPrivateKeyBase64,
		signingPrivateKeySeedHex: cfg.SigningPrivateKeySeedHex,
	}
}

func (m *Manager) Sign(_ context.Context, ref domain.KeyRef, payload []byte) ([]byte, error) {
	if err := validateKeyRef(ref); err != nil {
		return nil, err
	}
	key := m.lookupKey(ref)
	if key == nil {
		return nil, errors.New("private key not found")
	}
	return ed25519.Sign(key, payload), nil
}

func (m *Manager) Verify(_ context.Context, _ domain.KeyRef, payload []byte, sig []byte, pubKey []byte) error {
	return verifyEd25519(pubKey, payload, sig)
}

func (m *Manager) lookupKey(ref domain.KeyRef) ed25519.PrivateKey {
	if m == nil {
		return nil
	}
	if len(m.keys) > 0 {
		if key, ok := m.keys[keyRefKey(ref)]; ok {
			return key
		}
	}
	return loadConfiguredKey(ref, m)
}

func keyRefKey(ref domain.KeyRef) string {
	return ref.TenantID + "|" + string(ref.Purpose) + "|" + ref.KID
}

func loadConfiguredKey(ref domain.KeyRef, m *Manager) ed25519.PrivateKey {
	if m == nil {
		return nil
	}
	switch ref.Purpose {
	case domain.KeyPurposeLog:
		if key := readPrivateKeyBase64(m.logPrivateKeyBase64); key != nil {
			return key
		}
		if key := readPrivateKeyHex(m.logPrivateKeySeedHex); key != nil {
			return key
		}
	case domain.KeyPurposeSigning:
		if key := readPrivateKeyBase64(m.signingPrivateKeyBase64); key != nil {
			return key
		}
		if key := readPrivateKeyHex(m.signingPrivateKeySeedHex); key != nil {
			return key
		}
	}
	return nil
}

func readPrivateKeyBase64(value string) ed25519.PrivateKey {
	if value == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	key, err := parsePrivateKey(raw)
	if err != nil {
		return nil
	}
	return key
}

func readPrivateKeyHex(value string) ed25519.PrivateKey {
	if value == "" {
		return nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	key, err := parsePrivateKey(raw)
	if err != nil {
		return nil
	}
	return key
}

func parsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, errors.New("invalid ed25519 private key length")
	}
}

func verifyEd25519(pubKey, payload, sig []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key length")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid ed25519 signature length")
	}
	if !ed25519.Verify(pubKey, payload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func validateKeyRef(ref domain.KeyRef) error {
	if ref.TenantID == "" || ref.KID == "" || ref.Purpose == "" {
		return errors.New("key ref is required")
	}
	switch ref.Purpose {
	case domain.KeyPurposeSigning, domain.KeyPurposeLog:
		return nil
	default:
		return errors.New("unsupported key purpose")
	}
}
