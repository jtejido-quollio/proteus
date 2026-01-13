package usecase

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
)

type staticKeyRepo struct {
	keys    map[string]domain.SigningKey
	revoked map[string]bool
}

func (r *staticKeyRepo) GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error) {
	key, ok := r.keys[tenantID+":"+kid]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &key, nil
}

func (r *staticKeyRepo) IsRevoked(ctx context.Context, tenantID, kid string) (bool, error) {
	return r.revoked[tenantID+":"+kid], nil
}

type noopTenantRepo struct{}

func (r *noopTenantRepo) GetByID(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	return nil, domain.ErrNotFound
}

func (r *noopTenantRepo) Create(ctx context.Context, tenant domain.Tenant) error {
	return errors.New("not implemented")
}

type memoryManifestRepo struct{}

func (r *memoryManifestRepo) UpsertManifestAndEnvelope(ctx context.Context, env domain.SignedManifestEnvelope) (string, string, error) {
	return env.Manifest.ManifestID, "signed-id", nil
}

type keyVector struct {
	Alg             string `json:"alg"`
	KID             string `json:"kid"`
	PublicKeyBase64 string `json:"public_key_base64"`
	TenantID        string `json:"tenant_id"`
}

func TestRecordSignedManifest_VectorEnvelope(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	envBytes := readFile(t, filepath.Join(vectorsDir, "envelope_1.json"))
	var env domain.SignedManifestEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	keyBytes := readFile(t, filepath.Join(vectorsDir, "keys.json"))
	var keys keyVector
	if err := json.Unmarshal(keyBytes, &keys); err != nil {
		t.Fatalf("unmarshal keys.json: %v", err)
	}
	pubKey, err := base64.StdEncoding.DecodeString(keys.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	expectedLeafHex := strings.TrimSpace(string(readFile(t, filepath.Join(vectorsDir, "leaf_1.sha256.hex"))))
	expectedLeafHash, err := hex.DecodeString(expectedLeafHex)
	if err != nil {
		t.Fatalf("decode leaf hash: %v", err)
	}

	keyRepo := &staticKeyRepo{
		keys: map[string]domain.SigningKey{
			env.Manifest.TenantID + ":" + env.Signature.KID: {
				TenantID:  env.Manifest.TenantID,
				KID:       env.Signature.KID,
				Alg:       keys.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}

	uc := &RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     logmem.New(),
		Crypto:  &crypto.Service{},
	}

	resp, err := uc.Execute(context.Background(), RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("execute record: %v", err)
	}

	if !bytes.Equal(resp.LeafHash, expectedLeafHash) {
		t.Fatal("leaf hash mismatch with test vector")
	}
	if resp.Inclusion == nil || resp.STH == nil {
		t.Fatal("expected inclusion proof and STH")
	}

	ok, err := merkle.VerifyInclusionProof(
		resp.LeafHash,
		int(resp.Inclusion.LeafIndex),
		int(resp.Inclusion.STHTreeSize),
		resp.Inclusion.Path,
		resp.Inclusion.STHRootHash,
	)
	if err != nil {
		t.Fatalf("verify inclusion proof: %v", err)
	}
	if !ok {
		t.Fatal("expected inclusion proof to verify")
	}
}

func TestRecordSignedManifest_Idempotent(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	envBytes := readFile(t, filepath.Join(vectorsDir, "envelope_1.json"))
	var env domain.SignedManifestEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	keyBytes := readFile(t, filepath.Join(vectorsDir, "keys.json"))
	var keys keyVector
	if err := json.Unmarshal(keyBytes, &keys); err != nil {
		t.Fatalf("unmarshal keys.json: %v", err)
	}
	pubKey, err := base64.StdEncoding.DecodeString(keys.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	keyRepo := &staticKeyRepo{
		keys: map[string]domain.SigningKey{
			env.Manifest.TenantID + ":" + env.Signature.KID: {
				TenantID:  env.Manifest.TenantID,
				KID:       env.Signature.KID,
				Alg:       keys.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}

	uc := &RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     logmem.New(),
		Crypto:  &crypto.Service{},
	}

	first, err := uc.Execute(context.Background(), RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	second, err := uc.Execute(context.Background(), RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("second record: %v", err)
	}
	if first.LeafIndex != second.LeafIndex {
		t.Fatalf("expected same leaf index, got %d vs %d", first.LeafIndex, second.LeafIndex)
	}
	if first.STH == nil || second.STH == nil {
		t.Fatal("expected STH in responses")
	}
	if first.STH.TreeSize != second.STH.TreeSize || !bytes.Equal(first.STH.RootHash, second.STH.RootHash) {
		t.Fatal("expected idempotent STH")
	}
	if first.Inclusion == nil || second.Inclusion == nil {
		t.Fatal("expected inclusion proofs")
	}
	if first.Inclusion.STHTreeSize != second.Inclusion.STHTreeSize {
		t.Fatal("expected idempotent inclusion proof")
	}
	if !hashPathEqual(first.Inclusion.Path, second.Inclusion.Path) {
		t.Fatal("expected identical inclusion path")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func hashPathEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
