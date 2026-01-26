package awskms

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/awsclient"
)

type Manager struct {
	client *awsclient.Client
	env    string
}

func NewManager(client *awsclient.Client, env string) (*Manager, error) {
	if env == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	return &Manager{client: client, env: env}, nil
}

func NewManagerFromConfig(cfg config.Config) (*Manager, error) {
	if cfg.ProteusEnv == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	client, err := awsclient.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewManager(client, cfg.ProteusEnv)
}

func (m *Manager) Sign(ctx context.Context, ref domain.KeyRef, payload []byte) ([]byte, error) {
	if m == nil || m.client == nil {
		return nil, errors.New("aws manager not configured")
	}
	if err := validateKeyRef(ref); err != nil {
		return nil, err
	}
	secretID, err := secretName(m.env, ref)
	if err != nil {
		return nil, err
	}
	secretBytes, err := m.client.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	var key secretPayload
	if err := json.Unmarshal(secretBytes, &key); err != nil {
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
