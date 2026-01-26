//go:build integration
// +build integration

package usecase_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	dbinfra "proteus/internal/infra/db"
	"proteus/internal/infra/merkle"
	"proteus/internal/usecase"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

type staticLogKeyRepo struct {
	key domain.SigningKey
}

func (r *staticLogKeyRepo) GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error) {
	return &r.key, nil
}

type trackingCache struct {
	mu      sync.Mutex
	entries map[string]domain.VerificationResult
}

func newTrackingCache() *trackingCache {
	return &trackingCache{
		entries: make(map[string]domain.VerificationResult),
	}
}

func (c *trackingCache) Get(ctx context.Context, key string) (*domain.VerificationResult, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	value := entry
	return &value, true, nil
}

func (c *trackingCache) Put(ctx context.Context, key string, value domain.VerificationResult, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = value
	return nil
}

func TestVerifySignedManifest_CacheInvalidatesOnEpoch_BackedByDB(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_3.json"))
	keys := loadKeys(t, filepath.Join(vectorsDir, "keys.json"))
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

	insertTenant(t, db, env.Manifest.TenantID)

	keyRepo := &staticKeyRepo{
		keys: map[string]domain.SigningKey{
			env.Manifest.TenantID + ":" + env.Signature.KID: {
				TenantID:  env.Manifest.TenantID,
				KID:       env.Signature.KID,
				Purpose:   domain.KeyPurposeSigning,
				Alg:       keys.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}
	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       "log-key-epoch",
			Purpose:   domain.KeyPurposeLog,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}
	bundle := loadProofBundle(t, vectorsDir)

	epochRepo := dbinfra.NewRevocationEpochRepository(db)
	revRepo := dbinfra.NewRevocationRepository(db)
	revSvc := usecase.NewRevocationService(revRepo, epochRepo)
	cache := newTrackingCache()

	verifyUC := &usecase.VerifySignedManifest{
		Keys:             keyRepo,
		LogKeys:          logKeyRepo,
		Crypto:           &crypto.Service{},
		Merkle:           &merkle.Service{},
		RevocationEpochs: epochRepo,
		Cache:            cache,
	}

	first, err := verifyUC.Execute(context.Background(), usecase.VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest (first): %v", err)
	}
	leafHash, err := verifyUC.Crypto.ComputeLeafHash(env)
	if err != nil {
		t.Fatalf("compute leaf hash: %v", err)
	}
	keyEpoch0 := verificationCacheKey(env.Manifest.TenantID, leafHash, &bundle.STH, first.RevocationEpoch)
	if _, ok := cache.entries[keyEpoch0]; !ok {
		t.Fatalf("expected cache entry for epoch %d", first.RevocationEpoch)
	}

	revocation := domain.Revocation{
		TenantID:  env.Manifest.TenantID,
		KID:       env.Signature.KID,
		RevokedAt: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	}
	if _, err := revSvc.Revoke(context.Background(), revocation); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	second, err := verifyUC.Execute(context.Background(), usecase.VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest (second): %v", err)
	}
	if second.RevocationEpoch == first.RevocationEpoch {
		t.Fatalf("expected revocation epoch to change after revocation")
	}
	keyEpoch1 := verificationCacheKey(env.Manifest.TenantID, leafHash, &bundle.STH, second.RevocationEpoch)
	if _, ok := cache.entries[keyEpoch1]; !ok {
		t.Fatalf("expected cache entry for epoch %d", second.RevocationEpoch)
	}
	if keyEpoch0 == keyEpoch1 {
		t.Fatalf("expected cache key to change after epoch bump")
	}
}

func verificationCacheKey(tenantID string, leafHash []byte, sth *domain.STH, epoch int64) string {
	if tenantID == "" || len(leafHash) == 0 || sth == nil || len(sth.RootHash) == 0 {
		return ""
	}
	payload := make([]byte, 0, len(tenantID)+1+len(leafHash)+64)
	payload = append(payload, tenantID...)
	payload = append(payload, '|')
	payload = append(payload, []byte(hex.EncodeToString(leafHash))...)
	payload = append(payload, '|')
	payload = append(payload, []byte(strconv.FormatInt(sth.TreeSize, 10))...)
	payload = append(payload, '|')
	payload = append(payload, []byte(hex.EncodeToString(sth.RootHash))...)
	payload = append(payload, '|')
	payload = append(payload, []byte(strconv.FormatInt(epoch, 10))...)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type inclusionVector struct {
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
	TenantID    string   `json:"tenant_id"`
}

type sthVector struct {
	IssuedAt string `json:"issued_at"`
	RootHash string `json:"root_hash"`
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
}

type keyVector struct {
	Alg             string `json:"alg"`
	KID             string `json:"kid"`
	PublicKeyBase64 string `json:"public_key_base64"`
	TenantID        string `json:"tenant_id"`
}

func loadProofBundle(t *testing.T, vectorsDir string) *usecase.ProofBundle {
	t.Helper()
	inclusionBytes := readFile(t, filepath.Join(vectorsDir, "inclusion_proof_leaf_index_2.json"))
	var inclusionVec inclusionVector
	if err := json.Unmarshal(inclusionBytes, &inclusionVec); err != nil {
		t.Fatalf("unmarshal inclusion vector: %v", err)
	}
	sthBytes := readFile(t, filepath.Join(vectorsDir, "sth.json"))
	var sthVec sthVector
	if err := json.Unmarshal(sthBytes, &sthVec); err != nil {
		t.Fatalf("unmarshal sth: %v", err)
	}
	rootHash := decodeHex(t, sthVec.RootHash)
	issuedAt, err := time.Parse(time.RFC3339, sthVec.IssuedAt)
	if err != nil {
		t.Fatalf("parse issued_at: %v", err)
	}

	return &usecase.ProofBundle{
		STH: domain.STH{
			TenantID: sthVec.TenantID,
			TreeSize: sthVec.TreeSize,
			RootHash: rootHash,
			IssuedAt: issuedAt,
		},
		STHSignature: strings.TrimSpace(string(readFile(t, filepath.Join(vectorsDir, "sth.signature.b64")))),
		Inclusion: domain.InclusionProof{
			TenantID:    inclusionVec.TenantID,
			LeafIndex:   inclusionVec.LeafIndex,
			Path:        decodeHexPath(t, inclusionVec.Path),
			STHTreeSize: inclusionVec.STHTreeSize,
			STHRootHash: decodeHex(t, inclusionVec.STHRootHash),
		},
	}
}

func loadEnvelope(t *testing.T, path string) domain.SignedManifestEnvelope {
	t.Helper()
	var env domain.SignedManifestEnvelope
	if err := json.Unmarshal(readFile(t, path), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

func loadKeys(t *testing.T, path string) keyVector {
	t.Helper()
	var keys keyVector
	if err := json.Unmarshal(readFile(t, path), &keys); err != nil {
		t.Fatalf("unmarshal keys: %v", err)
	}
	return keys
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func decodeHexPath(t *testing.T, values []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(values))
	for _, val := range values {
		out = append(out, decodeHex(t, val))
	}
	return out
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return out
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN_TEST"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN_TEST not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	lockTestDB(t, db)
	applyMigrations(t, db)
	return db
}

func lockTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatalf("open db conn: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_lock(987654321)"); err != nil {
		_ = conn.Close()
		t.Fatalf("acquire db lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(987654321)")
		_ = conn.Close()
	})
}

func applyMigrations(t *testing.T, db *gorm.DB) {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".sql") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	for _, name := range files {
		sqlBytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if err := db.Exec(string(sqlBytes)).Error; err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
}

func resetDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`
		TRUNCATE tenants,
			signing_keys,
			revocations,
			manifests,
			signed_manifests,
			transparency_log_leaves,
			tree_heads,
			artifacts,
			provenance_edges,
			audit_events,
			tenant_audit_seq,
			tenant_revocation_epoch,
			anchor_receipts,
			anchor_attempts
		RESTART IDENTITY CASCADE`).Error; err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
}

func insertTenant(t *testing.T, db *gorm.DB, tenantID string) {
	t.Helper()
	if err := db.Create(&dbinfra.TenantModel{
		ID:        tenantID,
		Name:      "tenant-" + tenantID,
		CreatedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}
