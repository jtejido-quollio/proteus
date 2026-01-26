package http

import (
	"context"
	"testing"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
)

type stubKeyManager struct {
	sig    []byte
	called int
	ref    domain.KeyRef
}

func (s *stubKeyManager) Sign(_ context.Context, ref domain.KeyRef, payload []byte) ([]byte, error) {
	s.called++
	s.ref = ref
	if s.sig == nil {
		return nil, nil
	}
	out := make([]byte, len(s.sig))
	copy(out, s.sig)
	return out, nil
}

func (s *stubKeyManager) Verify(_ context.Context, _ domain.KeyRef, _ []byte, _ []byte, _ []byte) error {
	return nil
}

type stubLogKeyRepo struct {
	key domain.SigningKey
	err error
}

func (r *stubLogKeyRepo) GetActive(_ context.Context, _ string) (*domain.SigningKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	return &r.key, nil
}

func TestBuildLogSignerRejectsSigningKey(t *testing.T) {
	cryptoSvc := &crypto.Service{}
	manager := &stubKeyManager{sig: []byte("sig")}
	logKeys := &stubLogKeyRepo{
		key: domain.SigningKey{
			TenantID: "tenant-1",
			KID:      "kid-1",
			Purpose:  domain.KeyPurposeSigning,
		},
	}
	signer := buildLogSigner(config.Config{}, cryptoSvc, manager, logKeys)
	if signer == nil {
		t.Fatal("expected signer")
	}
	_, err := signer(domain.STH{
		TenantID: "tenant-1",
		TreeSize: 1,
		IssuedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected error for signing key purpose")
	}
	if manager.called != 0 {
		t.Fatalf("expected key manager not called, got %d", manager.called)
	}
}

func TestBuildLogSignerUsesLogKey(t *testing.T) {
	cryptoSvc := &crypto.Service{}
	manager := &stubKeyManager{sig: []byte("sig")}
	logKeys := &stubLogKeyRepo{
		key: domain.SigningKey{
			TenantID: "tenant-1",
			KID:      "kid-1",
			Purpose:  domain.KeyPurposeLog,
		},
	}
	signer := buildLogSigner(config.Config{}, cryptoSvc, manager, logKeys)
	if signer == nil {
		t.Fatal("expected signer")
	}
	sig, err := signer(domain.STH{
		TenantID: "tenant-1",
		TreeSize: 1,
		IssuedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sig) != "sig" {
		t.Fatalf("unexpected signature: %q", string(sig))
	}
	if manager.called != 1 {
		t.Fatalf("expected key manager called once, got %d", manager.called)
	}
	if manager.ref.TenantID != "tenant-1" || manager.ref.KID != "kid-1" || manager.ref.Purpose != domain.KeyPurposeLog {
		t.Fatalf("unexpected key ref: %+v", manager.ref)
	}
}
