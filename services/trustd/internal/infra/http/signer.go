package http

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
)

type logKeyProvider interface {
	GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error)
}

func buildLogSigner(cfg config.Config, cryptoSvc *crypto.Service, keyManager domain.KeyManager, logKeys logKeyProvider) func(domain.STH) ([]byte, error) {
	envSigner := loadLogSignerFromConfig(cfg, cryptoSvc)
	if cryptoSvc == nil {
		return envSigner
	}
	if keyManager == nil || logKeys == nil {
		return envSigner
	}

	return func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		key, err := logKeys.GetActive(context.Background(), sth.TenantID)
		if err != nil {
			if envSigner != nil {
				return envSigner(sth)
			}
			return nil, err
		}
		if key.Purpose != domain.KeyPurposeLog {
			if envSigner != nil {
				return envSigner(sth)
			}
			return nil, errors.New("log key purpose mismatch")
		}
		ref := domain.KeyRef{
			TenantID: sth.TenantID,
			Purpose:  key.Purpose,
			KID:      key.KID,
		}
		if ref.TenantID == "" {
			ref.TenantID = key.TenantID
		}
		sig, err := keyManager.Sign(context.Background(), ref, canonical)
		if err != nil {
			if envSigner != nil {
				return envSigner(sth)
			}
			return nil, err
		}
		return sig, nil
	}
}

func loadLogSignerFromConfig(cfg config.Config, cryptoSvc *crypto.Service) func(domain.STH) ([]byte, error) {
	if cryptoSvc == nil {
		return nil
	}
	var privKey ed25519.PrivateKey

	if b64 := cfg.LogPrivateKeyBase64; b64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil
		}
		switch len(decoded) {
		case ed25519.PrivateKeySize:
			privKey = ed25519.PrivateKey(decoded)
		case ed25519.SeedSize:
			privKey = ed25519.NewKeyFromSeed(decoded)
		default:
			return nil
		}
	}

	if privKey == nil {
		if seedHex := cfg.LogPrivateKeySeedHex; seedHex != "" {
			decoded, err := hex.DecodeString(seedHex)
			if err != nil {
				return nil
			}
			if len(decoded) != ed25519.SeedSize {
				return nil
			}
			privKey = ed25519.NewKeyFromSeed(decoded)
		}
	}

	if privKey == nil {
		return nil
	}

	return func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		if privKey == nil {
			return nil, errors.New("log signing key not configured")
		}
		return ed25519.Sign(privKey, canonical), nil
	}
}
