//go:build integration

package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/usecase"
)

func TestVaultManager_SignVerify(t *testing.T) {
	cfg := config.FromEnv()
	if cfg.VaultAddr == "" || cfg.VaultToken == "" || cfg.ProteusEnv == "" {
		t.Skip("vault env vars not set")
	}
	ctx := context.Background()

	store, err := NewStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	manager, err := NewManagerFromConfig(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(pubKey)
	kid := hex.EncodeToString(sum[:])
	tenantID := "tenant-" + kid[:12]
	ref := domain.KeyRef{
		TenantID: tenantID,
		Purpose:  domain.KeyPurposeSigning,
		KID:      kid,
	}
	material := usecase.KeyMaterial{
		Ref:        ref,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Alg:        "ed25519",
		Status:     domain.KeyStatusActive,
	}

	if err := store.Put(ctx, material); err != nil {
		t.Fatalf("vault put: %v", err)
	}
	defer func() { _ = store.Delete(ctx, ref) }()

	payload := []byte("vault-sign-test")
	sig, err := manager.Sign(ctx, ref, payload)
	if err != nil {
		t.Fatalf("vault sign: %v", err)
	}
	if err := manager.Verify(ctx, ref, payload, sig, pubKey); err != nil {
		t.Fatalf("vault verify: %v", err)
	}
}
