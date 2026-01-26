package vault

import (
	"strings"
	"testing"

	"proteus/internal/config"
	"proteus/internal/domain"
)

func TestNewManagerFromConfigRequiresEnv(t *testing.T) {
	cfg := config.Config{VaultAddr: "http://vault", VaultToken: "token"}
	_, err := NewManagerFromConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "PROTEUS_ENV") {
		t.Fatalf("expected PROTEUS_ENV error, got %v", err)
	}
}

func TestNewStoreFromConfigRequiresEnv(t *testing.T) {
	cfg := config.Config{VaultAddr: "http://vault", VaultToken: "token"}
	_, err := NewStoreFromConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "PROTEUS_ENV") {
		t.Fatalf("expected PROTEUS_ENV error, got %v", err)
	}
}

func TestVaultPathScoping(t *testing.T) {
	ref := domain.KeyRef{
		TenantID: "tenant-1",
		Purpose:  domain.KeyPurposeLog,
		KID:      "kid-1",
	}
	path, err := vaultPath("dev", ref)
	if err != nil {
		t.Fatalf("vault path: %v", err)
	}
	expected := "secret/data/proteus/dev/tenants/tenant-1/keys/log/kid-1"
	if path != expected {
		t.Fatalf("unexpected vault path: %s", path)
	}
}

func TestVaultPathRejectsInvalidPurpose(t *testing.T) {
	ref := domain.KeyRef{
		TenantID: "tenant-1",
		Purpose:  domain.KeyPurpose("invalid"),
		KID:      "kid-1",
	}
	if _, err := vaultPath("dev", ref); err == nil {
		t.Fatal("expected error for invalid purpose")
	}
}
