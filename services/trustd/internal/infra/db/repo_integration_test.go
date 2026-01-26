//go:build integration
// +build integration

package db

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestTenantRepository_CreateGet(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	repo := NewTenantRepository(db)
	tenantID := mustUUID(t)
	now := time.Date(2026, 1, 22, 16, 0, 0, 0, time.UTC)
	tenant := domain.Tenant{
		ID:        tenantID,
		Name:      "tenant-" + tenantID[:8],
		CreatedAt: now,
	}
	if err := repo.Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	got, err := repo.GetByID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if tenant.ID != got.ID || tenant.Name != got.Name || !tenant.CreatedAt.Equal(got.CreatedAt) {
		t.Fatal("tenant mismatch")
	}
}

func TestSigningKeyRepository_GetList(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	keyID := mustUUID(t)
	model := SigningKeyModel{
		ID:        keyID,
		TenantID:  tenantID,
		KID:       "kid-1",
		Purpose:   string(domain.KeyPurposeSigning),
		Alg:       "ed25519",
		PublicKey: bytes.Repeat([]byte{0x01}, 32),
		Status:    string(domain.KeyStatusActive),
		CreatedAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := db.Create(&model).Error; err != nil {
		t.Fatalf("insert signing key: %v", err)
	}

	repo := NewSigningKeyRepository(db)
	got, err := repo.GetByKID(context.Background(), tenantID, "kid-1")
	if err != nil {
		t.Fatalf("get by kid: %v", err)
	}
	if got.KID != "kid-1" || got.TenantID != tenantID {
		t.Fatal("unexpected signing key data")
	}

	list, err := repo.ListByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 signing key, got %d", len(list))
	}
}

func TestLogKeyRepository_GetActiveList(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	oldActive := SigningKeyModel{
		ID:        mustUUID(t),
		TenantID:  tenantID,
		KID:       "kid-old",
		Purpose:   string(domain.KeyPurposeLog),
		Alg:       "ed25519",
		PublicKey: bytes.Repeat([]byte{0x02}, 32),
		Status:    string(domain.KeyStatusActive),
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	newActive := SigningKeyModel{
		ID:        mustUUID(t),
		TenantID:  tenantID,
		KID:       "kid-new",
		Purpose:   string(domain.KeyPurposeLog),
		Alg:       "ed25519",
		PublicKey: bytes.Repeat([]byte{0x03}, 32),
		Status:    string(domain.KeyStatusActive),
		CreatedAt: time.Now().UTC().Add(-time.Hour),
	}
	retired := SigningKeyModel{
		ID:        mustUUID(t),
		TenantID:  tenantID,
		KID:       "kid-retired",
		Purpose:   string(domain.KeyPurposeLog),
		Alg:       "ed25519",
		PublicKey: bytes.Repeat([]byte{0x04}, 32),
		Status:    string(domain.KeyStatusRetired),
		CreatedAt: time.Now().UTC().Add(-3 * time.Hour),
	}
	if err := db.Create(&oldActive).Error; err != nil {
		t.Fatalf("insert old active key: %v", err)
	}
	if err := db.Create(&newActive).Error; err != nil {
		t.Fatalf("insert new active key: %v", err)
	}
	if err := db.Create(&retired).Error; err != nil {
		t.Fatalf("insert retired key: %v", err)
	}

	repo := NewLogKeyRepository(db)
	active, err := repo.GetActive(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get active log key: %v", err)
	}
	if active.KID != "kid-new" {
		t.Fatalf("unexpected active log key: %s", active.KID)
	}

	all, err := repo.ListByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list log keys: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 log keys, got %d", len(all))
	}
}

func TestRevocationRepository_RevokeAndCheck(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	repo := NewRevocationRepository(db)
	revoked, err := repo.IsRevoked(context.Background(), tenantID, "kid-1")
	if err != nil {
		t.Fatalf("check revoked: %v", err)
	}
	if revoked {
		t.Fatal("expected key to be not revoked")
	}

	rev := domain.Revocation{
		TenantID:  tenantID,
		KID:       "kid-1",
		RevokedAt: time.Now().UTC().Add(-time.Minute),
		Reason:    "test",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.Revoke(context.Background(), rev); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if err := repo.Revoke(context.Background(), rev); err != nil {
		t.Fatalf("revoke key again: %v", err)
	}

	revoked, err = repo.IsRevoked(context.Background(), tenantID, "kid-1")
	if err != nil {
		t.Fatalf("check revoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected key to be revoked")
	}
}

func TestManifestRepository_UpsertAndGet(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	manifestID := mustUUID(t)
	createdAt := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)
	manifest := domain.Manifest{
		Schema:     "trust.manifest.v0",
		ManifestID: manifestID,
		TenantID:   tenantID,
		Subject: domain.Subject{
			Type:      "artifact",
			MediaType: "text/plain",
			Hash: domain.Hash{
				Alg:   "sha256",
				Value: "deadbeef",
			},
		},
		Actor: domain.Actor{
			Type: "service",
			ID:   "svc",
		},
		Tool: domain.Tool{
			Name:    "tool",
			Version: "1.0.0",
		},
		Time: domain.ManifestTime{
			CreatedAt:   createdAt,
			SubmittedAt: createdAt,
		},
	}
	sigBytes := bytes.Repeat([]byte{0x05}, 64)
	env := domain.SignedManifestEnvelope{
		Manifest: manifest,
		Signature: domain.Signature{
			Alg:   "ed25519",
			KID:   "kid-1",
			Value: base64.StdEncoding.EncodeToString(sigBytes),
		},
	}

	repo := NewManifestRepository(db)
	gotManifestID, signedID, err := repo.UpsertManifestAndEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("upsert manifest: %v", err)
	}
	if gotManifestID != manifestID {
		t.Fatalf("unexpected manifest id: %s", gotManifestID)
	}
	if signedID == "" {
		t.Fatal("expected signed manifest id")
	}

	readEnv, err := repo.GetEnvelopeByManifestID(context.Background(), tenantID, manifestID)
	if err != nil {
		t.Fatalf("get envelope by manifest id: %v", err)
	}
	if !reflect.DeepEqual(env.Manifest, readEnv.Manifest) {
		t.Fatal("manifest mismatch")
	}
	if !reflect.DeepEqual(env.Signature, readEnv.Signature) {
		t.Fatal("signature mismatch")
	}

	leafHash := bytes.Repeat([]byte{0x06}, 32)
	if err := db.Create(&TransparencyLeafModel{
		TenantID:         tenantID,
		LeafIndex:        0,
		LeafHash:         leafHash,
		SignedManifestID: signedID,
		CreatedAt:        time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("insert leaf: %v", err)
	}
	leafEnv, err := repo.GetEnvelopeByLeafHash(context.Background(), tenantID, leafHash)
	if err != nil {
		t.Fatalf("get envelope by leaf hash: %v", err)
	}
	if leafEnv.Manifest.ManifestID != manifestID {
		t.Fatal("unexpected manifest id for leaf hash")
	}
}

func TestProvenanceRepository_UpsertAndQuery(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	manifestID := mustUUID(t)
	manifest := ManifestModel{
		ID:               manifestID,
		TenantID:         tenantID,
		SubjectHashAlg:   "sha256",
		SubjectHashValue: "deadbeef",
		SubjectMediaType: "text/plain",
		ManifestJSON:     []byte(`{}`),
		CreatedAt:        time.Now().UTC(),
	}
	if err := db.Create(&manifest).Error; err != nil {
		t.Fatalf("insert manifest: %v", err)
	}

	repo := NewProvenanceRepository(db)
	artifact := domain.Artifact{
		TenantID:  tenantID,
		Hash:      domain.Hash{Alg: "sha256", Value: "inputhash"},
		MediaType: "text/plain",
		CreatedAt: time.Now().UTC(),
	}
	artifactID, err := repo.UpsertArtifact(context.Background(), tenantID, artifact)
	if err != nil {
		t.Fatalf("upsert artifact: %v", err)
	}
	if artifactID == "" {
		t.Fatal("expected artifact id")
	}

	edge := domain.ProvenanceEdge{
		TenantID:   tenantID,
		ManifestID: manifestID,
		Type:       domain.ProvenanceEdgeGenerated,
		ArtifactID: artifactID,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.AddEdge(context.Background(), edge); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	manifestIDs, err := repo.ListGeneratedManifestIDs(context.Background(), tenantID, artifact.Hash)
	if err != nil {
		t.Fatalf("list generated manifests: %v", err)
	}
	if len(manifestIDs) != 1 || manifestIDs[0] != manifestID {
		t.Fatalf("unexpected manifest ids: %v", manifestIDs)
	}
}

func TestTransparencyLogRepository_AppendAndSTH(t *testing.T) {
	db := setupTestDB(t)
	resetDB(t, db)

	tenantID := mustUUID(t)
	insertTenant(t, db, tenantID)

	manifestID := mustUUID(t)
	signedID := mustUUID(t)
	if err := db.Create(&ManifestModel{
		ID:               manifestID,
		TenantID:         tenantID,
		SubjectHashAlg:   "sha256",
		SubjectHashValue: "bead",
		SubjectMediaType: "text/plain",
		ManifestJSON:     []byte(`{"manifest_id":"` + manifestID + `"}`),
		CreatedAt:        time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("insert manifest: %v", err)
	}
	if err := db.Create(&SignedManifestModel{
		ID:         signedID,
		TenantID:   tenantID,
		ManifestID: manifestID,
		KID:        "kid-1",
		SigAlg:     "ed25519",
		Signature:  bytes.Repeat([]byte{0x07}, 64),
		ReceivedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("insert signed manifest: %v", err)
	}

	repo := NewTransparencyLogRepository(db)
	leaf1 := bytes.Repeat([]byte{0x08}, 32)
	leaf2 := bytes.Repeat([]byte{0x09}, 32)

	index1, err := repo.AppendLeaf(context.Background(), tenantID, signedID, leaf1)
	if err != nil {
		t.Fatalf("append leaf 1: %v", err)
	}
	index2, err := repo.AppendLeaf(context.Background(), tenantID, signedID, leaf2)
	if err != nil {
		t.Fatalf("append leaf 2: %v", err)
	}
	if index1 != 0 || index2 != 1 {
		t.Fatalf("unexpected leaf indexes: %d, %d", index1, index2)
	}

	indexAgain, err := repo.AppendLeaf(context.Background(), tenantID, signedID, leaf1)
	if err != nil {
		t.Fatalf("append duplicate leaf: %v", err)
	}
	if indexAgain != 0 {
		t.Fatalf("expected duplicate leaf index 0, got %d", indexAgain)
	}

	hashes, err := repo.ListLeafHashes(context.Background(), tenantID, 0)
	if err != nil {
		t.Fatalf("list leaf hashes: %v", err)
	}
	if len(hashes) != 2 || !bytes.Equal(hashes[0], leaf1) || !bytes.Equal(hashes[1], leaf2) {
		t.Fatal("unexpected leaf hash order")
	}

	sth := domain.TreeHead{
		TenantID:  tenantID,
		TreeSize:  2,
		RootHash:  bytes.Repeat([]byte{0x0a}, 32),
		IssuedAt:  time.Now().UTC(),
		Signature: bytes.Repeat([]byte{0x0b}, 64),
	}
	if err := repo.StoreSTH(context.Background(), sth); err != nil {
		t.Fatalf("store sth: %v", err)
	}
	got, err := repo.GetLatestSTH(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get latest sth: %v", err)
	}
	if got.TreeSize != sth.TreeSize || !bytes.Equal(got.RootHash, sth.RootHash) {
		t.Fatal("sth mismatch")
	}

	gotBySize, err := repo.GetSTHBySize(context.Background(), tenantID, 2)
	if err != nil {
		t.Fatalf("get sth by size: %v", err)
	}
	if gotBySize.TreeSize != sth.TreeSize || !bytes.Equal(gotBySize.RootHash, sth.RootHash) {
		t.Fatal("sth size mismatch")
	}
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
	dir := filepath.Join("..", "..", "..", "migrations")
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
	if err := db.Create(&TenantModel{
		ID:        tenantID,
		Name:      "tenant-" + tenantID[:8],
		CreatedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}

func mustUUID(t *testing.T) string {
	t.Helper()
	id, err := newUUID()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	return id
}
