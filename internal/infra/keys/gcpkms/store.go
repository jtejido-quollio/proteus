package gcpkms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/gcpclient"
	"proteus/internal/usecase"
)

type Store struct {
	client *gcpclient.Client
	env    string
}

type secretPayload struct {
	Alg              string `json:"alg"`
	KID              string `json:"kid"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	PublicKeyBase64  string `json:"public_key_base64"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at,omitempty"`
}

func NewStore(client *gcpclient.Client, env string) (*Store, error) {
	if env == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	return &Store{client: client, env: env}, nil
}

func NewStoreFromConfig(cfg config.Config) (*Store, error) {
	if cfg.ProteusEnv == "" {
		return nil, errors.New("PROTEUS_ENV is required")
	}
	client, err := gcpclient.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewStore(client, cfg.ProteusEnv)
}

func (s *Store) Put(ctx context.Context, material usecase.KeyMaterial) error {
	if s == nil || s.client == nil {
		return errors.New("gcp store not configured")
	}
	if err := validateKeyRef(material.Ref); err != nil {
		return err
	}
	if len(material.PrivateKey) == 0 || len(material.PublicKey) == 0 {
		return errors.New("private and public key are required")
	}
	payload := secretPayload{
		Alg:              material.Alg,
		KID:              material.Ref.KID,
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(material.PrivateKey),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(material.PublicKey),
		Status:           string(material.Status),
	}
	if !material.CreatedAt.IsZero() {
		payload.CreatedAt = material.CreatedAt.UTC().Format(time.RFC3339)
	}
	secretID, err := secretName(s.env, material.Ref)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.client.AddSecretVersion(ctx, secretID, encoded)
}

func (s *Store) Delete(ctx context.Context, ref domain.KeyRef) error {
	if s == nil || s.client == nil {
		return errors.New("gcp store not configured")
	}
	if err := validateKeyRef(ref); err != nil {
		return err
	}
	secretID, err := secretName(s.env, ref)
	if err != nil {
		return err
	}
	return s.client.DeleteSecret(ctx, secretID)
}
