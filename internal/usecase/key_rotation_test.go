package usecase

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
)

type memoryKeyRepo struct {
	keys    map[string]domain.SigningKey
	revoked map[string]bool
}

func newMemoryKeyRepo() *memoryKeyRepo {
	return &memoryKeyRepo{
		keys:    make(map[string]domain.SigningKey),
		revoked: make(map[string]bool),
	}
}

func (r *memoryKeyRepo) GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error) {
	key, ok := r.keys[tenantID+":"+kid]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &key, nil
}

func (r *memoryKeyRepo) IsRevoked(ctx context.Context, tenantID, kid string) (bool, error) {
	return r.revoked[tenantID+":"+kid], nil
}

func (r *memoryKeyRepo) GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error) {
	var active *domain.SigningKey
	for _, key := range r.keys {
		if key.TenantID != tenantID || key.Status != domain.KeyStatusActive {
			continue
		}
		copyKey := key
		if active == nil || key.CreatedAt.After(active.CreatedAt) {
			active = &copyKey
		}
	}
	if active == nil {
		return nil, domain.ErrNotFound
	}
	return active, nil
}

func (r *memoryKeyRepo) Create(ctx context.Context, key domain.SigningKey) error {
	r.keys[key.TenantID+":"+key.KID] = key
	return nil
}

func (r *memoryKeyRepo) UpdateStatus(ctx context.Context, tenantID, kid string, status domain.KeyStatus) error {
	key, ok := r.keys[tenantID+":"+kid]
	if !ok {
		return domain.ErrNotFound
	}
	key.Status = status
	r.keys[tenantID+":"+kid] = key
	return nil
}

func (r *memoryKeyRepo) WithTx(ctx context.Context, fn func(store KeyRotationStore) error) error {
	return fn(r)
}

type memoryKeyMaterialStore struct {
	keys map[string]ed25519.PrivateKey
}

func newMemoryKeyMaterialStore() *memoryKeyMaterialStore {
	return &memoryKeyMaterialStore{keys: make(map[string]ed25519.PrivateKey)}
}

func (s *memoryKeyMaterialStore) Put(ctx context.Context, material KeyMaterial) error {
	s.keys[material.Ref.TenantID+":"+material.Ref.KID] = ed25519.PrivateKey(material.PrivateKey)
	return nil
}

func (s *memoryKeyMaterialStore) Delete(ctx context.Context, ref domain.KeyRef) error {
	delete(s.keys, ref.TenantID+":"+ref.KID)
	return nil
}

func TestKeyRotation_RetiredKeysStillVerify(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_1.json"))
	envNew := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_2.json"))
	keys := loadKeys(t, filepath.Join(vectorsDir, "keys.json"))
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

	keyRepo := newMemoryKeyRepo()
	keyRepo.keys[env.Manifest.TenantID+":"+env.Signature.KID] = domain.SigningKey{
		TenantID:  env.Manifest.TenantID,
		KID:       env.Signature.KID,
		Purpose:   domain.KeyPurposeSigning,
		Alg:       keys.Alg,
		PublicKey: pubKey,
		Status:    domain.KeyStatusActive,
		CreatedAt: time.Now().Add(-time.Hour),
	}

	logPrivKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	logPubKey := logPrivKey.Public().(ed25519.PublicKey)
	logKey := domain.SigningKey{
		TenantID:  env.Manifest.TenantID,
		KID:       "log-key-1",
		Purpose:   domain.KeyPurposeLog,
		Alg:       "ed25519",
		PublicKey: logPubKey,
		Status:    domain.KeyStatusActive,
	}

	cryptoSvc := &crypto.Service{}
	signSTH := func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(logPrivKey, canonical), nil
	}
	log := logmem.NewWithSignerAndClock(signSTH, func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) })

	recordUC := &RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     log,
		Crypto:  cryptoSvc,
	}
	recordResp, err := recordUC.Execute(context.Background(), RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("record signed manifest: %v", err)
	}

	materialStore := newMemoryKeyMaterialStore()
	rotation := &KeyRotationService{
		SigningStore: keyRepo,
		LogStore:     keyRepo,
		Material:     materialStore,
		Clock:        func() time.Time { return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) },
	}
	newKey, err := rotation.Rotate(context.Background(), env.Manifest.TenantID, domain.KeyPurposeSigning)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	verifyUC := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: &staticLogKeyRepo{key: logKey},
		Crypto:  cryptoSvc,
		Merkle:  &merkle.Service{},
	}
	sthSigB64 := base64.StdEncoding.EncodeToString(recordResp.STH.Signature)
	_, err = verifyUC.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope: env,
		ProofBundle: &ProofBundle{
			STH:          *recordResp.STH,
			STHSignature: sthSigB64,
			Inclusion:    *recordResp.Inclusion,
		},
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify retired key receipt: %v", err)
	}

	privKey := materialStore.keys[env.Manifest.TenantID+":"+newKey.KID]
	canonical, err := cryptoSvc.CanonicalizeManifest(envNew.Manifest)
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	sig := ed25519.Sign(privKey, canonical)
	envNew.Signature.KID = newKey.KID
	envNew.Signature.Value = base64.StdEncoding.EncodeToString(sig)

	if _, err := recordUC.Execute(context.Background(), RecordSignedManifestRequest{Envelope: envNew}); err != nil {
		t.Fatalf("record signed manifest with new key: %v", err)
	}

	keyRepo.revoked[env.Manifest.TenantID+":"+env.Signature.KID] = true
	_, err = verifyUC.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope: env,
		ProofBundle: &ProofBundle{
			STH:          *recordResp.STH,
			STHSignature: sthSigB64,
			Inclusion:    *recordResp.Inclusion,
		},
		RequireProof: true,
	})
	if err == nil || err != domain.ErrKeyRevoked {
		t.Fatalf("expected key revoked error, got %v", err)
	}
}
