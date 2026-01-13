package capture

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func ParseEd25519PrivateKeyHex(value string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return parseEd25519PrivateKey(raw)
}

func ParseEd25519PrivateKeyBase64(value string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return parseEd25519PrivateKey(raw)
}

func ParseEd25519PublicKeyHex(value string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return parseEd25519PublicKey(raw)
}

func ParseEd25519PublicKeyBase64(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return parseEd25519PublicKey(raw)
}

func parseEd25519PrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		key := ed25519.NewKeyFromSeed(raw)
		return append(ed25519.PrivateKey(nil), key...), nil
	case ed25519.PrivateKeySize:
		return append(ed25519.PrivateKey(nil), raw...), nil
	default:
		return nil, errors.New("invalid ed25519 private key length")
	}
}

func parseEd25519PublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key length")
	}
	return append(ed25519.PublicKey(nil), raw...), nil
}
