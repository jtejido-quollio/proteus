package soft

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"proteus/internal/domain"
)

func TestManager_SignRejectsWrongPurpose(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	manager := NewManager(map[domain.KeyRef]ed25519.PrivateKey{
		{TenantID: "tenant-1", Purpose: domain.KeyPurposeSigning, KID: "kid-1"}: privKey,
	})

	_, err = manager.Sign(context.Background(), domain.KeyRef{
		TenantID: "tenant-1",
		Purpose:  domain.KeyPurposeLog,
		KID:      "kid-1",
	}, []byte("payload"))
	if err == nil {
		t.Fatal("expected error for signing with wrong purpose")
	}
}

func TestManager_SignRejectsMissingRef(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	manager := NewManager(map[domain.KeyRef]ed25519.PrivateKey{
		{TenantID: "tenant-1", Purpose: domain.KeyPurposeSigning, KID: "kid-1"}: privKey,
	})

	_, err = manager.Sign(context.Background(), domain.KeyRef{
		TenantID: "tenant-1",
		KID:      "kid-1",
	}, []byte("payload"))
	if err == nil {
		t.Fatal("expected error for missing key ref fields")
	}
}
