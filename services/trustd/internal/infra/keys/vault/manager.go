package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/vaultclient"
)

type Manager struct {
	client *vaultclient.Client
	env    string
}

type storedKey struct {
	Alg              string `json:"alg"`
	KID              string `json:"kid"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	PublicKeyBase64  string `json:"public_key_base64"`
	Status           string `json:"status"`
}

func NewManager(client *vaultclient.Client, env string) (*Manager, error) {
	if env == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	return &Manager{client: client, env: env}, nil
}

func NewManagerFromConfig(cfg config.Config) (*Manager, error) {
	if cfg.ProteusEnv == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	if cfg.VaultAddr == "" || cfg.VaultToken == "" {
		return nil, errors.New("VAULT_ADDR and VAULT_TOKEN are required")
	}
	return NewManager(vaultclient.New(cfg.VaultAddr, cfg.VaultToken), cfg.ProteusEnv)
}

func (m *Manager) Sign(ctx context.Context, ref domain.KeyRef, payload []byte) ([]byte, error) {
	if m == nil || m.client == nil {
		return nil, errors.New("vault manager not configured")
	}
	if ref.TenantID == "" || ref.Purpose == "" || ref.KID == "" {
		return nil, errors.New("key ref is required")
	}
	path, err := vaultPath(m.env, ref)
	if err != nil {
		return nil, err
	}
	var key storedKey
	if err := m.client.ReadKV(ctx, path, &key); err != nil {
		return nil, err
	}
	if key.Alg != "" && !strings.EqualFold(key.Alg, "ed25519") {
		return nil, errors.New("unsupported key algorithm")
	}
	if key.KID != "" && key.KID != ref.KID {
		return nil, errors.New("kid mismatch")
	}
	privKey, err := parsePrivateKeyBase64(key.PrivateKeyBase64)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privKey, payload), nil
}

func (m *Manager) Verify(_ context.Context, _ domain.KeyRef, payload []byte, sig []byte, pubKey []byte) error {
	return verifyEd25519(pubKey, payload, sig)
}

func parsePrivateKeyBase64(value string) (ed25519.PrivateKey, error) {
	if value == "" {
		return nil, errors.New("private_key_base64 is required")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
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
