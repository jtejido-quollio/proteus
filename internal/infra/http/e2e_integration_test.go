//go:build integration
// +build integration

package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/db"
	"proteus/internal/infra/logdb"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/usecase"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestPhase1Smoke_E2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)

	cryptoSvc := &crypto.Service{}
	log := logmem.NewWithSignerAndClock(func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(privKey, canonical), nil
	}, func() time.Time {
		return time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)
	})

	signingRepo := db.NewSigningKeyRepository(dbConn)
	logKeyRepo := db.NewLogKeyRepository(dbConn)
	revRepo := db.NewRevocationRepository(dbConn)
	tenantRepo := db.NewTenantRepository(dbConn)
	manifestRepo := db.NewManifestRepository(dbConn)
	keyRepo := db.NewKeyRepository(signingRepo, revRepo)

	recordUC := &usecase.RecordSignedManifest{
		Tenants: tenantRepo,
		Keys:    keyRepo,
		Manif:   manifestRepo,
		Log:     log,
		Crypto:  cryptoSvc,
	}
	verifyUC := &usecase.VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Log:     log,
		Crypto:  cryptoSvc,
		Merkle:  &merkle.Service{},
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Record:      recordUC,
		Verify:      verifyUC,
		Tenants:     tenantRepo,
		SigningKeys: signingRepo,
		LogKeys:     logKeyRepo,
		Revocations: revRepo,
		AdminAPIKey: "secret",
	})

	tenantID := keys.TenantID
	createTenantWithID(t, server, "secret", tenantID)
	registerKey(t, server, "secret", tenantID, keys.PublicKeyBase64)
	registerLogKey(t, server, "secret", tenantID, keys.PublicKeyBase64)

	envelopeBytes := readVectorFile(t, "envelope_3.json")

	recordResp := recordEnvelope(t, server, envelopeBytes)
	verifyResp := verifyEnvelope(t, server, envelopeBytes, recordResp)
	if !verifyResp.SignatureValid || !verifyResp.LogIncluded {
		t.Fatal("expected verify to succeed")
	}

	revokeKey(t, server, "secret", tenantID, keys.KID)
	_, err := verifyEnvelopeExpectError(t, server, envelopeBytes, recordResp)
	if err == nil {
		t.Fatal("expected verification to fail after revocation")
	}
}

func TestLogEndpoints_DBBacked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)

	cryptoSvc := &crypto.Service{}
	fixedTime := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)

	tenantRepo := db.NewTenantRepository(dbConn)
	manifestRepo := db.NewManifestRepository(dbConn)
	logRepo := db.NewTransparencyLogRepository(dbConn)

	ctx := context.Background()
	tenant := domain.Tenant{
		ID:        keys.TenantID,
		Name:      "tenant",
		CreatedAt: fixedTime,
	}
	if err := tenantRepo.Create(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	env1 := loadEnvelope(t, "envelope_1.json")
	env2 := loadEnvelope(t, "envelope_2.json")
	_, signed1, err := manifestRepo.UpsertManifestAndEnvelope(ctx, env1)
	if err != nil {
		t.Fatalf("upsert envelope 1: %v", err)
	}
	_, signed2, err := manifestRepo.UpsertManifestAndEnvelope(ctx, env2)
	if err != nil {
		t.Fatalf("upsert envelope 2: %v", err)
	}

	leaf1, err := cryptoSvc.ComputeLeafHash(env1)
	if err != nil {
		t.Fatalf("leaf hash 1: %v", err)
	}
	leaf2, err := cryptoSvc.ComputeLeafHash(env2)
	if err != nil {
		t.Fatalf("leaf hash 2: %v", err)
	}

	log := logdb.NewWithSignerAndClock(logRepo, func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(privKey, canonical), nil
	}, func() time.Time {
		return fixedTime
	})

	if _, _, _, err := log.AppendLeaf(ctx, keys.TenantID, signed1, leaf1); err != nil {
		t.Fatalf("append leaf 1: %v", err)
	}
	if _, _, _, err := log.AppendLeaf(ctx, keys.TenantID, signed2, leaf2); err != nil {
		t.Fatalf("append leaf 2: %v", err)
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{Log: log})

	t.Run("latest sth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/logs/"+keys.TenantID+"/sth/latest", nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp sthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode sth response: %v", err)
		}
		if resp.TreeSize != 2 {
			t.Fatalf("unexpected tree size: %d", resp.TreeSize)
		}
	})

	t.Run("inclusion proof", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/logs/"+keys.TenantID+"/inclusion/"+hex.EncodeToString(leaf1), nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp logInclusionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode inclusion response: %v", err)
		}
		if resp.LeafIndex != 0 {
			t.Fatalf("unexpected leaf index: %d", resp.LeafIndex)
		}
	})

	t.Run("consistency proof", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/logs/"+keys.TenantID+"/consistency?from=1&to=2", nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp consistencyResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode consistency response: %v", err)
		}
		if resp.FromSize != 1 || resp.ToSize != 2 {
			t.Fatalf("unexpected sizes: %d -> %d", resp.FromSize, resp.ToSize)
		}
	})
}

func createTenantWithID(t *testing.T, server *Server, adminKey, tenantID string) {
	t.Helper()
	body := []byte(`{"name":"tenant","tenant_id":"` + tenantID + `"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", adminKey)
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create tenant failed: %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode tenant response: %v", err)
	}
	if resp["tenant_id"] != tenantID {
		t.Fatalf("unexpected tenant_id: %s", resp["tenant_id"])
	}
}

func registerKey(t *testing.T, server *Server, adminKey, tenantID, pubKey string) {
	t.Helper()
	body := map[string]string{
		"kid":        "tenant-key-001",
		"alg":        "ed25519",
		"public_key": pubKey,
	}
	postAdmin(t, server, adminKey, "/v1/tenants/"+tenantID+"/keys/signing", body)
}

func registerLogKey(t *testing.T, server *Server, adminKey, tenantID, pubKey string) {
	t.Helper()
	body := map[string]string{
		"kid":        "tenant-log-001",
		"alg":        "ed25519",
		"public_key": pubKey,
	}
	postAdmin(t, server, adminKey, "/v1/tenants/"+tenantID+"/keys/log", body)
}

func revokeKey(t *testing.T, server *Server, adminKey, tenantID, kid string) {
	t.Helper()
	body := map[string]string{
		"reason": "test",
	}
	postAdmin(t, server, adminKey, "/v1/tenants/"+tenantID+"/keys/"+kid+":revoke", body)
}

func postAdmin(t *testing.T, server *Server, adminKey, path string, payload any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", adminKey)
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin POST %s failed: %d", path, w.Code)
	}
}

func recordEnvelope(t *testing.T, server *Server, envelopeBytes []byte) recordResponse {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record", bytes.NewReader(envelopeBytes))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("record failed: %d", w.Code)
	}
	var resp recordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode record response: %v", err)
	}
	return resp
}

func verifyEnvelope(t *testing.T, server *Server, envelopeBytes []byte, recordResp recordResponse) verifyResponse {
	t.Helper()
	resp, err := verifyEnvelopeExpectError(t, server, envelopeBytes, recordResp)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	return *resp
}

func verifyEnvelopeExpectError(t *testing.T, server *Server, envelopeBytes []byte, recordResp recordResponse) (*verifyResponse, error) {
	t.Helper()
	reqBody := verifyRequestRaw{
		Envelope: envelopeBytes,
		Proof: &proofInput{
			STH: sthInput{
				TreeSize:  recordResp.STH.TreeSize,
				RootHash:  recordResp.STH.RootHash,
				IssuedAt:  recordResp.STH.IssuedAt,
				Signature: recordResp.STH.Signature,
			},
			Inclusion: inclusionInput{
				LeafIndex:   recordResp.InclusionProof.LeafIndex,
				Path:        recordResp.InclusionProof.Path,
				STHTreeSize: recordResp.InclusionProof.STHTreeSize,
				STHRootHash: recordResp.InclusionProof.STHRootHash,
			},
		},
	}
	body, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		var errResp errorResponse
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		return nil, errors.New(errResp.Code)
	}
	var resp verifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN_TEST"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN_TEST not set")
	}
	dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	applyMigrations(t, dbConn)
	return dbConn
}

func applyMigrations(t *testing.T, dbConn *gorm.DB) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "migrations", "0001_init.sql")
	sqlBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	if err := dbConn.Exec(string(sqlBytes)).Error; err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
}

func resetDB(t *testing.T, dbConn *gorm.DB) {
	t.Helper()
	if err := dbConn.Exec(`
		TRUNCATE tenants,
			signing_keys,
			revocations,
			manifests,
			signed_manifests,
			transparency_log_leaves,
			tree_heads
		RESTART IDENTITY CASCADE`).Error; err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
}
