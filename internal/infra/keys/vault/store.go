package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/vaultclient"
	"proteus/internal/usecase"
)

type Store struct {
	client *vaultclient.Client
	env    string
}

type vaultKeyPayload struct {
	Alg              string `json:"alg"`
	KID              string `json:"kid"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	PublicKeyBase64  string `json:"public_key_base64"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at,omitempty"`
}

func NewStore(client *vaultclient.Client, env string) (*Store, error) {
	if env == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	return &Store{client: client, env: env}, nil
}

func NewStoreFromConfig(cfg config.Config) (*Store, error) {
	if cfg.ProteusEnv == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	if cfg.VaultAddr == "" || cfg.VaultToken == "" {
		return nil, errors.New("VAULT_ADDR and VAULT_TOKEN are required")
	}
	return NewStore(vaultclient.New(cfg.VaultAddr, cfg.VaultToken), cfg.ProteusEnv)
}

func (s *Store) Put(ctx context.Context, material usecase.KeyMaterial) error {
	if s == nil || s.client == nil {
		return errors.New("vault store not configured")
	}
	if material.Ref.TenantID == "" || material.Ref.KID == "" || material.Ref.Purpose == "" {
		return errors.New("key ref is required")
	}
	if len(material.PrivateKey) == 0 || len(material.PublicKey) == 0 {
		return errors.New("private and public key are required")
	}
	payload := vaultKeyPayload{
		Alg:              material.Alg,
		KID:              material.Ref.KID,
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(material.PrivateKey),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(material.PublicKey),
		Status:           string(material.Status),
	}
	if !material.CreatedAt.IsZero() {
		payload.CreatedAt = material.CreatedAt.UTC().Format(time.RFC3339)
	}
	path, err := vaultPath(s.env, material.Ref)
	if err != nil {
		return err
	}
	return s.client.WriteKV(ctx, path, payload)
}

func (s *Store) Delete(ctx context.Context, ref domain.KeyRef) error {
	if s == nil || s.client == nil {
		return errors.New("vault store not configured")
	}
	if ref.TenantID == "" || ref.KID == "" || ref.Purpose == "" {
		return errors.New("key ref is required")
	}
	path, err := vaultPath(s.env, ref)
	if err != nil {
		return err
	}
	return s.client.DeleteKV(ctx, path)
}
