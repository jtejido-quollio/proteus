//go:build integration
// +build integration

package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/anchor"
	"proteus/internal/infra/anchor/rekor"
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

	server := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Record:        recordUC,
		Verify:        verifyUC,
		Tenants:       tenantRepo,
		SigningKeys:   signingRepo,
		LogKeys:       logKeyRepo,
		Revocations:   revRepo,
		AdminAPIKey:   "secret",
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	tenantID := keys.TenantID
	createTenantWithID(t, server, "secret", tenantID)
	registerKey(t, server, "secret", tenantID, keys.PublicKeyBase64)
	registerLogKey(t, server, "secret", tenantID, keys.PublicKeyBase64)

	envelopeBytes := readVectorFile(t, "envelope_3.json")

	recordResp := recordEnvelope(t, server, envelopeBytes, tenantID)
	verifyResp := verifyEnvelope(t, server, envelopeBytes, recordResp, tenantID)
	if !verifyResp.SignatureValid || !verifyResp.LogIncluded {
		t.Fatal("expected verify to succeed")
	}

	revokeKey(t, server, "secret", tenantID, keys.KID)
	_, err := verifyEnvelopeExpectError(t, server, envelopeBytes, recordResp, tenantID)
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

	server := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Log:           log,
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	t.Run("latest sth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/logs/"+keys.TenantID+"/sth/latest", nil)
		addAuthHeader(req, keys.TenantID)
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
		addAuthHeader(req, keys.TenantID)
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
		addAuthHeader(req, keys.TenantID)
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

func TestLineageDerivationHandlers_ErrorsAndLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := keys.PublicKeyBase64

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
	revRepo := db.NewRevocationRepository(dbConn)
	tenantRepo := db.NewTenantRepository(dbConn)
	manifestRepo := db.NewManifestRepository(dbConn)
	provRepo := db.NewProvenanceRepository(dbConn)
	keyRepo := db.NewKeyRepository(signingRepo, revRepo)

	recordUC := &usecase.RecordSignedManifest{
		Tenants:    tenantRepo,
		Keys:       keyRepo,
		Manif:      manifestRepo,
		Log:        log,
		Crypto:     cryptoSvc,
		Provenance: provRepo,
	}

	server := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Record:        recordUC,
		Provenance:    &usecase.ProvenanceQuery{Manifests: manifestRepo, Provenance: provRepo},
		Tenants:       tenantRepo,
		SigningKeys:   signingRepo,
		Revocations:   revRepo,
		AdminAPIKey:   "secret",
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	tenantID := keys.TenantID
	createTenantWithID(t, server, "secret", tenantID)
	registerKey(t, server, "secret", tenantID, pubKey)

	childManifestID := "00000000-0000-0000-0000-000000000003"
	rootManifestID := "00000000-0000-0000-0000-000000000004"
	childHash := domain.Hash{Alg: "sha256", Value: strings.Repeat("a", 64)}
	rootHash := domain.Hash{Alg: "sha256", Value: strings.Repeat("b", 64)}
	now := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)
	kid := "tenant-key-001"

	childEnv := buildSignedEnvelope(t, cryptoSvc, tenantID, childManifestID, kid, privKey, childHash, nil, now)
	rootEnv := buildSignedEnvelope(t, cryptoSvc, tenantID, rootManifestID, kid, privKey, rootHash, []domain.InputArtifact{
		{MediaType: "text/plain", Hash: childHash},
	}, now)

	recordEnvelope(t, server, mustMarshalEnvelope(t, childEnv), tenantID)
	recordEnvelope(t, server, mustMarshalEnvelope(t, rootEnv), tenantID)

	t.Run("lineage missing auth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+rootHash.Value, nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		resp := decodeErrorResponse(t, w)
		if resp.Code != "UNAUTHORIZED" {
			t.Fatalf("expected UNAUTHORIZED, got %s", resp.Code)
		}
	})

	t.Run("lineage invalid hash cases", func(t *testing.T) {
		cases := []string{
			strings.Repeat("a", 63),
			strings.Repeat("z", 64),
		}
		for _, hash := range cases {
			t.Run(hash, func(t *testing.T) {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+hash, nil)
				addAuthHeader(req, tenantID)
				server.r.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d", w.Code)
				}
				resp := decodeErrorResponse(t, w)
				if resp.Code != "INVALID_HASH" {
					t.Fatalf("expected INVALID_HASH, got %s", resp.Code)
				}
			})
		}
	})

	t.Run("derivation invalid tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/derivation/"+rootManifestID, nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		resp := decodeErrorResponse(t, w)
		if resp.Code != "UNAUTHORIZED" {
			t.Fatalf("expected UNAUTHORIZED, got %s", resp.Code)
		}
	})

	t.Run("derivation invalid manifest id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/derivation/%20", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		resp := decodeErrorResponse(t, w)
		if resp.Code != "INVALID_MANIFEST_ID" {
			t.Fatalf("expected INVALID_MANIFEST_ID, got %s", resp.Code)
		}
	})

	t.Run("lineage max_depth=0 truncates when children exist", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+rootHash.Value+"?max_depth=0", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp usecase.LineageResult
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode lineage: %v", err)
		}
		if !resp.Truncated {
			t.Fatalf("expected truncated true")
		}
		if !containsString(resp.Limits.Hit, "max_depth") {
			t.Fatalf("expected max_depth in limits.hit")
		}
		if resp.Limits.MaxDepth != 0 {
			t.Fatalf("expected max_depth 0, got %d", resp.Limits.MaxDepth)
		}
	})

	t.Run("lineage max_depth=0 without children", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+childHash.Value+"?max_depth=0", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp usecase.LineageResult
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode lineage: %v", err)
		}
		if resp.Truncated {
			t.Fatalf("expected truncated false")
		}
		if len(resp.Limits.Hit) != 0 {
			t.Fatalf("expected no limits.hit entries")
		}
	})

	t.Run("lineage invalid max_depth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+rootHash.Value+"?max_depth=-1", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		resp := decodeErrorResponse(t, w)
		if resp.Code != "INVALID_QUERY" {
			t.Fatalf("expected INVALID_QUERY, got %s", resp.Code)
		}
	})

	t.Run("lineage max_nodes truncation", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lineage/"+rootHash.Value+"?max_nodes=1", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp usecase.LineageResult
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode lineage: %v", err)
		}
		if !resp.Truncated {
			t.Fatalf("expected truncated true")
		}
		if !containsString(resp.Limits.Hit, "max_nodes") {
			t.Fatalf("expected max_nodes in limits.hit")
		}
	})

	t.Run("derivation limits reflect params", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/derivation/"+rootManifestID+"?max_depth=3&max_nodes=9", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp usecase.DerivationView
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode derivation: %v", err)
		}
		if resp.Limits.MaxDepth != 3 || resp.Limits.MaxNodes != 9 {
			t.Fatalf("unexpected limits: depth=%d nodes=%d", resp.Limits.MaxDepth, resp.Limits.MaxNodes)
		}
		if resp.Truncated {
			t.Fatalf("expected derivation not truncated")
		}
	})

	t.Run("derivation truncation max_depth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/derivation/"+rootManifestID+"?max_depth=0", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp usecase.DerivationView
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode derivation: %v", err)
		}
		if !resp.Truncated {
			t.Fatalf("expected derivation truncated")
		}
		if !containsString(resp.Limits.Hit, "max_depth") {
			t.Fatalf("expected max_depth in limits.hit")
		}
	})

	t.Run("derivation invalid max_nodes", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/derivation/"+rootManifestID+"?max_nodes=-1", nil)
		addAuthHeader(req, tenantID)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		resp := decodeErrorResponse(t, w)
		if resp.Code != "INVALID_QUERY" {
			t.Fatalf("expected INVALID_QUERY, got %s", resp.Code)
		}
	})
}

func TestRecordAnchoringFailureDoesNotBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)
	fixedTime := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)

	cryptoSvc := &crypto.Service{}
	logSigner := func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(privKey, canonical), nil
	}

	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	}
	signer := rekorSigner{priv: privKey, pub: privKey.Public().(ed25519.PublicKey)}
	rekorClient, err := rekor.NewClient("https://rekor.invalid", "rekor_public", signer, httpClient)
	if err != nil {
		t.Fatalf("new rekor client: %v", err)
	}

	anchorAttemptRepo := db.NewAnchorAttemptRepository(dbConn)
	anchorReceiptRepo := db.NewAnchorReceiptRepository(dbConn)
	anchorSvc, err := anchor.NewService([]anchor.Provider{rekorClient}, []string{"rekor"}, anchorAttemptRepo, anchorReceiptRepo)
	if err != nil {
		t.Fatalf("new anchor service: %v", err)
	}

	log := logmem.NewWithSignerClockAndAnchor(logSigner, func() time.Time { return fixedTime }, anchorSvc, time.Second)

	signingRepo := db.NewSigningKeyRepository(dbConn)
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

	server := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Record:        recordUC,
		Tenants:       tenantRepo,
		SigningKeys:   signingRepo,
		Revocations:   revRepo,
		AdminAPIKey:   "secret",
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	tenantID := keys.TenantID
	createTenantWithID(t, server, "secret", tenantID)
	registerKey(t, server, "secret", tenantID, keys.PublicKeyBase64)

	envelopeBytes := readVectorFile(t, "envelope_1.json")
	recordResp := recordEnvelope(t, server, envelopeBytes, tenantID)

	root, err := hex.DecodeString(recordResp.STH.RootHash)
	if err != nil {
		t.Fatalf("decode root hash: %v", err)
	}
	signature := decodeBase64(t, recordResp.STH.Signature)
	payload, err := anchor.BuildPayload(tenantID, domain.STH{
		TreeSize:  recordResp.STH.TreeSize,
		RootHash:  root,
		Signature: signature,
	})
	if err != nil {
		t.Fatalf("build anchor payload: %v", err)
	}
	attempts, err := anchorAttemptRepo.ListByPayloadHash(context.Background(), tenantID, payload.HashHex)
	if err != nil {
		t.Fatalf("list anchor attempts: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 anchor attempt, got %d", len(attempts))
	}
	if attempts[0].Status != domain.AnchorStatusFailed || attempts[0].ErrorCode != domain.AnchorErrorNetwork {
		t.Fatalf("unexpected anchor attempt status/error: %s/%s", attempts[0].Status, attempts[0].ErrorCode)
	}

	receipts, err := anchorReceiptRepo.ListByPayloadHash(context.Background(), tenantID, payload.HashHex)
	if err != nil {
		t.Fatalf("list anchor receipts: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("expected no anchor receipts, got %d", len(receipts))
	}
}

func TestRecordAnchoringPersistenceFailureDoesNotBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)
	fixedTime := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)

	cryptoSvc := &crypto.Service{}
	logSigner := func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(privKey, canonical), nil
	}

	provider := stubAnchorProvider{
		id:       "rekor",
		bundleID: "rekor_public",
		receipt:  domain.AnchorReceipt{Status: domain.AnchorStatusAnchored},
	}
	attempts := &failingAttemptRepo{}
	receipts := &failingReceiptRepo{}
	anchorSvc, err := anchor.NewService([]anchor.Provider{provider}, []string{"rekor"}, attempts, receipts)
	if err != nil {
		t.Fatalf("new anchor service: %v", err)
	}

	anchorReceipts, err := anchorSvc.AnchorSTH(context.Background(), keys.TenantID, domain.STH{
		TreeSize:  1,
		RootHash:  bytes.Repeat([]byte{0x01}, 32),
		Signature: bytes.Repeat([]byte{0x02}, 64),
	})
	if err != nil {
		t.Fatalf("anchor sth: %v", err)
	}
	if len(anchorReceipts) != 1 {
		t.Fatalf("expected 1 anchor receipt, got %d", len(anchorReceipts))
	}
	if anchorReceipts[0].Status != domain.AnchorStatusFailed || anchorReceipts[0].ErrorCode != domain.AnchorErrorPersistence {
		t.Fatalf("unexpected status/error: %s/%s", anchorReceipts[0].Status, anchorReceipts[0].ErrorCode)
	}

	log := logmem.NewWithSignerClockAndAnchor(logSigner, func() time.Time { return fixedTime }, anchorSvc, time.Second)

	signingRepo := db.NewSigningKeyRepository(dbConn)
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

	server := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Record:        recordUC,
		Tenants:       tenantRepo,
		SigningKeys:   signingRepo,
		Revocations:   revRepo,
		AdminAPIKey:   "secret",
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	tenantID := keys.TenantID
	createTenantWithID(t, server, "secret", tenantID)
	registerKey(t, server, "secret", tenantID, keys.PublicKeyBase64)

	envelopeBytes := readVectorFile(t, "envelope_1.json")
	_ = recordEnvelope(t, server, envelopeBytes, tenantID)
	if attempts.calls == 0 {
		t.Fatal("expected attempt persistence to be invoked")
	}
	if receipts.calls != 0 {
		t.Fatalf("expected no receipt persistence, got %d", receipts.calls)
	}
}

func TestRecordAnchoringSuccessPersistsReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dbConn := setupTestDB(t)
	resetDB(t, dbConn)

	keys := loadKeys(t)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)
	fixedTime := time.Date(2026, 1, 12, 5, 0, 0, 0, time.UTC)

	cryptoSvc := &crypto.Service{}
	logSigner := func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(privKey, canonical), nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/log/entries":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uuid-123":{"logIndex":7}}`))
		case "/api/v1/log/entries/uuid-123":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uuid-123":{"logIndex":7,"integratedTime":1700000000}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	signer := rekorSigner{priv: privKey, pub: privKey.Public().(ed25519.PublicKey)}
	rekorClient, err := rekor.NewClient(server.URL, "rekor_public", signer, server.Client())
	if err != nil {
		t.Fatalf("new rekor client: %v", err)
	}

	anchorAttemptRepo := db.NewAnchorAttemptRepository(dbConn)
	anchorReceiptRepo := db.NewAnchorReceiptRepository(dbConn)
	anchorSvc, err := anchor.NewService([]anchor.Provider{rekorClient}, []string{"rekor"}, anchorAttemptRepo, anchorReceiptRepo)
	if err != nil {
		t.Fatalf("new anchor service: %v", err)
	}

	log := logmem.NewWithSignerClockAndAnchor(logSigner, func() time.Time { return fixedTime }, anchorSvc, time.Second)

	signingRepo := db.NewSigningKeyRepository(dbConn)
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

	serverHTTP := NewServerWithDeps(config.Config{AuthMode: "oidc"}, ServerDeps{
		Record:        recordUC,
		Tenants:       tenantRepo,
		SigningKeys:   signingRepo,
		Revocations:   revRepo,
		AdminAPIKey:   "secret",
		Authenticator: &staticAuthenticator{},
		Authorizer:    &allowAuthorizer{},
	})

	tenantID := keys.TenantID
	createTenantWithID(t, serverHTTP, "secret", tenantID)
	registerKey(t, serverHTTP, "secret", tenantID, keys.PublicKeyBase64)

	envelopeBytes := readVectorFile(t, "envelope_1.json")
	recordResp := recordEnvelope(t, serverHTTP, envelopeBytes, tenantID)

	root, err := hex.DecodeString(recordResp.STH.RootHash)
	if err != nil {
		t.Fatalf("decode root hash: %v", err)
	}
	signature := decodeBase64(t, recordResp.STH.Signature)
	payload, err := anchor.BuildPayload(tenantID, domain.STH{
		TreeSize:  recordResp.STH.TreeSize,
		RootHash:  root,
		Signature: signature,
	})
	if err != nil {
		t.Fatalf("build anchor payload: %v", err)
	}

	attempts, err := anchorAttemptRepo.ListByPayloadHash(context.Background(), tenantID, payload.HashHex)
	if err != nil {
		t.Fatalf("list anchor attempts: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 anchor attempt, got %d", len(attempts))
	}
	if attempts[0].Status != domain.AnchorStatusAnchored {
		t.Fatalf("unexpected attempt status: %s", attempts[0].Status)
	}

	receipts, err := anchorReceiptRepo.ListByPayloadHash(context.Background(), tenantID, payload.HashHex)
	if err != nil {
		t.Fatalf("list anchor receipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 anchor receipt, got %d", len(receipts))
	}
	if receipts[0].Status != domain.AnchorStatusAnchored {
		t.Fatalf("unexpected receipt status: %s", receipts[0].Status)
	}
	if receipts[0].EntryUUID == "" {
		t.Fatal("expected receipt entry uuid")
	}
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

func recordEnvelope(t *testing.T, server *Server, envelopeBytes []byte, tenantID string) recordResponse {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record", bytes.NewReader(envelopeBytes))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(req, tenantID)
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

func buildSignedEnvelope(t *testing.T, cryptoSvc *crypto.Service, tenantID, manifestID, kid string, privKey ed25519.PrivateKey, subjectHash domain.Hash, inputs []domain.InputArtifact, ts time.Time) domain.SignedManifestEnvelope {
	t.Helper()
	manifest := domain.Manifest{
		Schema:     "trust.manifest.v0",
		ManifestID: manifestID,
		TenantID:   tenantID,
		Subject: domain.Subject{
			Type:      "artifact",
			MediaType: "text/plain",
			Hash:      subjectHash,
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
			CreatedAt:   ts,
			SubmittedAt: ts,
		},
		Inputs: inputs,
	}
	canonical, err := cryptoSvc.CanonicalizeManifest(manifest)
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	signature := ed25519.Sign(privKey, canonical)
	return domain.SignedManifestEnvelope{
		Manifest: manifest,
		Signature: domain.Signature{
			Alg:   "ed25519",
			KID:   kid,
			Value: base64.StdEncoding.EncodeToString(signature),
		},
	}
}

func mustMarshalEnvelope(t *testing.T, env domain.SignedManifestEnvelope) []byte {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return body
}

func verifyEnvelope(t *testing.T, server *Server, envelopeBytes []byte, recordResp recordResponse, tenantID string) verifyResponse {
	t.Helper()
	resp, err := verifyEnvelopeExpectError(t, server, envelopeBytes, recordResp, tenantID)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	return *resp
}

func verifyEnvelopeExpectError(t *testing.T, server *Server, envelopeBytes []byte, recordResp recordResponse, tenantID string) (*verifyResponse, error) {
	t.Helper()
	reqBody := verifyRequestRaw{
		Envelope: envelopeBytes,
		Proof: &proofInput{
			STH: sthInput{
				TenantID:  recordResp.STH.TenantID,
				TreeSize:  recordResp.STH.TreeSize,
				RootHash:  recordResp.STH.RootHash,
				IssuedAt:  recordResp.STH.IssuedAt,
				Signature: recordResp.STH.Signature,
			},
			Inclusion: inclusionInput{
				TenantID:    recordResp.InclusionProof.TenantID,
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
	addAuthHeader(req, tenantID)
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

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var resp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return resp
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
	lockTestDB(t, dbConn)
	applyMigrations(t, dbConn)
	return dbConn
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

func applyMigrations(t *testing.T, dbConn *gorm.DB) {
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
		if err := dbConn.Exec(string(sqlBytes)).Error; err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
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

type rekorSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s rekorSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	return ed25519.Sign(s.priv, payload), s.pub, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type stubAnchorProvider struct {
	id       string
	bundleID string
	receipt  domain.AnchorReceipt
}

func (s stubAnchorProvider) ProviderName() string { return s.id }
func (s stubAnchorProvider) BundleID() string     { return s.bundleID }
func (s stubAnchorProvider) Anchor(ctx context.Context, payload anchor.Payload) domain.AnchorReceipt {
	return s.receipt
}

type failingAttemptRepo struct {
	calls int
}

func (r *failingAttemptRepo) Append(ctx context.Context, attempt domain.AnchorAttempt) error {
	r.calls++
	return errors.New("persist attempt failed")
}

func (r *failingAttemptRepo) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorAttempt, error) {
	return nil, nil
}

type failingReceiptRepo struct {
	calls int
}

func (r *failingReceiptRepo) AppendAnchored(ctx context.Context, receipt domain.AnchorReceipt) error {
	r.calls++
	return errors.New("persist receipt failed")
}

func (r *failingReceiptRepo) ListByPayloadHash(ctx context.Context, tenantID, payloadHash string) ([]domain.AnchorReceipt, error) {
	return nil, nil
}
