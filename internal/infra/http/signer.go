package http

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
)

func loadLogSignerFromEnv(cryptoSvc *crypto.Service) func(domain.STH) ([]byte, error) {
	if cryptoSvc == nil {
		return nil
	}
	var privKey ed25519.PrivateKey

	if b64 := os.Getenv("LOG_PRIVATE_KEY_BASE64"); b64 != "" {
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
		if seedHex := os.Getenv("LOG_PRIVATE_KEY_SEED_HEX"); seedHex != "" {
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
		return ed25519.Sign(privKey, canonical), nil
	}
}
