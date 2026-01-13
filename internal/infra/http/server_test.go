package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proteus/internal/config"
	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/usecase"

	"github.com/gin-gonic/gin"
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
	if r.key.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	return &r.key, nil
}

type memoryManifestRepo struct{}

func (r *memoryManifestRepo) UpsertManifestAndEnvelope(ctx context.Context, env domain.SignedManifestEnvelope) (string, string, error) {
	return env.Manifest.ManifestID, "signed-id", nil
}

type memTenantStore struct {
	mu      sync.Mutex
	tenants map[string]domain.Tenant
}

func (m *memTenantStore) Create(ctx context.Context, tenant domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tenants == nil {
		m.tenants = make(map[string]domain.Tenant)
	}
	if _, ok := m.tenants[tenant.ID]; ok {
		return gorm.ErrDuplicatedKey
	}
	m.tenants[tenant.ID] = tenant
	return nil
}

type memKeyStore struct {
	mu   sync.Mutex
	keys map[string][]domain.SigningKey
}

func (m *memKeyStore) Create(ctx context.Context, key domain.SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = make(map[string][]domain.SigningKey)
	}
	for _, existing := range m.keys[key.TenantID] {
		if existing.KID == key.KID {
			return gorm.ErrDuplicatedKey
		}
	}
	m.keys[key.TenantID] = append(m.keys[key.TenantID], key)
	return nil
}

func (m *memKeyStore) ListByTenant(ctx context.Context, tenantID string) ([]domain.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		return []domain.SigningKey{}, nil
	}
	keys := m.keys[tenantID]
	out := make([]domain.SigningKey, len(keys))
	copy(out, keys)
	return out, nil
}

type memRevocationStore struct {
	mu          sync.Mutex
	revocations map[string]domain.Revocation
}

func (m *memRevocationStore) Revoke(ctx context.Context, rev domain.Revocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revocations == nil {
		m.revocations = make(map[string]domain.Revocation)
	}
	m.revocations[rev.TenantID+":"+rev.KID] = rev
	return nil
}

type memKeyRepo struct {
	keys        *memKeyStore
	revocations *memRevocationStore
}

func (m *memKeyRepo) GetByKID(ctx context.Context, tenantID, kid string) (*domain.SigningKey, error) {
	if m.keys == nil {
		return nil, domain.ErrNotFound
	}
	list, _ := m.keys.ListByTenant(ctx, tenantID)
	for _, key := range list {
		if key.KID == kid {
			return &key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *memKeyRepo) IsRevoked(ctx context.Context, tenantID, kid string) (bool, error) {
	if m.revocations == nil {
		return false, nil
	}
	m.revocations.mu.Lock()
	defer m.revocations.mu.Unlock()
	_, ok := m.revocations.revocations[tenantID+":"+kid]
	return ok, nil
}

type keyVector struct {
	Alg             string `json:"alg"`
	KID             string `json:"kid"`
	PublicKeyBase64 string `json:"public_key_base64"`
	SeedHex         string `json:"seed_hex"`
	TenantID        string `json:"tenant_id"`
}

type sthVector struct {
	IssuedAt string `json:"issued_at"`
	RootHash string `json:"root_hash"`
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
}

type inclusionVector struct {
	LeafHash    string   `json:"leaf_hash"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHRootHash string   `json:"sth_root_hash"`
	STHTreeSize int64    `json:"sth_tree_size"`
	TenantID    string   `json:"tenant_id"`
}

type verifyRequestRaw struct {
	Envelope json.RawMessage `json:"envelope"`
	Artifact *artifactInput  `json:"artifact,omitempty"`
	Proof    *proofInput     `json:"proof,omitempty"`
	Options  *verifyOptions  `json:"options,omitempty"`
}

func TestRecordEndpoint_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	env := loadEnvelope(t, "envelope_1.json")
	keys := loadKeys(t)
	leafHex := loadLeafHex(t, "leaf_1.sha256.hex")
	pubKey := decodeBase64(t, keys.PublicKeyBase64)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)

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

	recordUC := &usecase.RecordSignedManifest{
		Keys:   keyRepo,
		Manif:  &memoryManifestRepo{},
		Log:    log,
		Crypto: cryptoSvc,
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Record: recordUC,
	})

	body := readVectorFile(t, "envelope_1.json")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	var resp recordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ManifestID != env.Manifest.ManifestID {
		t.Fatalf("unexpected manifest_id: %s", resp.ManifestID)
	}
	if resp.LeafHash != leafHex {
		t.Fatalf("unexpected leaf_hash: %s", resp.LeafHash)
	}
	if resp.STH.Signature == "" {
		t.Fatal("expected sth signature")
	}
}

func TestRecordEndpoint_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Record: &usecase.RecordSignedManifest{},
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	assertErrorCode(t, w.Body.Bytes(), "INVALID_JSON")
}

func TestVerifyEndpoint_SuccessWithProof(t *testing.T) {
	gin.SetMode(gin.TestMode)
	env := loadEnvelope(t, "envelope_3.json")
	keys := loadKeys(t)
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

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

	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       keys.KID,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}

	verifyUC := &usecase.VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Verify: verifyUC,
	})

	proof := loadProofRequest(t)
	reqBody := verifyRequestRaw{
		Envelope: readVectorFile(t, "envelope_3.json"),
		Proof:    &proof,
	}

	body, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	var resp verifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.SignatureValid || !resp.LogIncluded {
		t.Fatal("expected signature_valid and log_included")
	}
	if resp.STH == nil || resp.InclusionProof == nil {
		t.Fatal("expected proof in response")
	}
}

func TestVerifyEndpoint_Failures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	env := loadEnvelope(t, "envelope_3.json")
	keys := loadKeys(t)
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

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
	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       keys.KID,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}
	verifyUC := &usecase.VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}
	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Verify: verifyUC,
	})

	proof := loadProofRequest(t)
	reqBody := verifyRequestRaw{
		Envelope: readVectorFile(t, "envelope_3.json"),
		Proof:    &proof,
	}

	t.Run("signature invalid", func(t *testing.T) {
		bad := reqBody
		var envCopy domain.SignedManifestEnvelope
		if err := json.Unmarshal(bad.Envelope, &envCopy); err != nil {
			t.Fatalf("unmarshal env: %v", err)
		}
		envCopy.Signature.Value = "AAAA"
		envBytes, _ := json.Marshal(envCopy)
		bad.Envelope = envBytes
		body, _ := json.Marshal(bad)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "SIGNATURE_INVALID")
	})

	t.Run("key unknown", func(t *testing.T) {
		badVerify := &usecase.VerifySignedManifest{
			Keys:    &staticKeyRepo{keys: map[string]domain.SigningKey{}, revoked: map[string]bool{}},
			LogKeys: logKeyRepo,
			Crypto:  &crypto.Service{},
			Merkle:  &merkle.Service{},
		}
		badServer := NewServerWithDeps(config.Config{}, ServerDeps{Verify: badVerify})
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		badServer.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "KEY_UNKNOWN")
	})

	t.Run("key revoked", func(t *testing.T) {
		revoked := &staticKeyRepo{
			keys: map[string]domain.SigningKey{
				env.Manifest.TenantID + ":" + env.Signature.KID: {
					TenantID:  env.Manifest.TenantID,
					KID:       env.Signature.KID,
					Alg:       keys.Alg,
					PublicKey: pubKey,
					Status:    domain.KeyStatusActive,
				},
			},
			revoked: map[string]bool{
				env.Manifest.TenantID + ":" + env.Signature.KID: true,
			},
		}
		badVerify := &usecase.VerifySignedManifest{
			Keys:    revoked,
			LogKeys: logKeyRepo,
			Crypto:  &crypto.Service{},
			Merkle:  &merkle.Service{},
		}
		badServer := NewServerWithDeps(config.Config{}, ServerDeps{Verify: badVerify})
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		badServer.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "KEY_REVOKED")
	})

	t.Run("proof invalid", func(t *testing.T) {
		bad := reqBody
		proof := loadProofRequest(t)
		proof.Inclusion.Path[0] = strings.Repeat("0", len(proof.Inclusion.Path[0]))
		bad.Proof = &proof
		body, _ := json.Marshal(bad)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "LOG_PROOF_INVALID")
	})

	t.Run("sth invalid", func(t *testing.T) {
		bad := reqBody
		proof := loadProofRequest(t)
		proof.STH.Signature = "AAAA"
		bad.Proof = &proof
		body, _ := json.Marshal(bad)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "STH_INVALID")
	})

	t.Run("artifact hash mismatch", func(t *testing.T) {
		bad := reqBody
		bad.Proof = nil
		bad.Options = nil
		artifact := []byte(`{}`)
		bad.Artifact = &artifactInput{
			MediaType:   "application/json",
			BytesBase64: base64.StdEncoding.EncodeToString(artifact),
		}
		body, _ := json.Marshal(bad)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "ARTIFACT_HASH_MISMATCH")
	})

	t.Run("proof required", func(t *testing.T) {
		bad := reqBody
		bad.Proof = nil
		bad.Options = &verifyOptions{RequireProof: true}
		body, _ := json.Marshal(bad)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		assertErrorCode(t, w.Body.Bytes(), "PROOF_REQUIRED")
	})
}

func TestKeyDiscoveryEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	keys := loadKeys(t)
	pubKey := decodeBase64(t, keys.PublicKeyBase64)
	keyStore := &memKeyStore{}
	key := domain.SigningKey{
		TenantID:  keys.TenantID,
		KID:       keys.KID,
		Alg:       keys.Alg,
		PublicKey: pubKey,
		Status:    domain.KeyStatusActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := keyStore.Create(context.Background(), key); err != nil {
		t.Fatalf("create key: %v", err)
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		SigningKeys: keyStore,
		LogKeys:     keyStore,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+keys.TenantID+"/keys/signing", nil)
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp []keyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 || resp[0].PublicKey != keys.PublicKeyBase64 {
		t.Fatal("unexpected signing key response")
	}
}

func TestAdminEndpoints_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := NewServerWithDeps(config.Config{}, ServerDeps{
		AdminAPIKey: "secret",
		Tenants:     &memTenantStore{},
	})
	body := []byte(`{"name":"tenant"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertErrorCode(t, w.Body.Bytes(), "UNAUTHORIZED")
}

func TestAdminEndpoints_Authorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenantStore := &memTenantStore{}
	keyStore := &memKeyStore{}
	revocations := &memRevocationStore{}
	server := NewServerWithDeps(config.Config{}, ServerDeps{
		AdminAPIKey: "secret",
		Tenants:     tenantStore,
		SigningKeys: keyStore,
		LogKeys:     keyStore,
		Revocations: revocations,
	})

	tenantBody := []byte(`{"name":"tenant"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tenants", bytes.NewReader(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", "secret")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var tenantResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &tenantResp); err != nil {
		t.Fatalf("decode tenant response: %v", err)
	}
	tenantID := tenantResp["tenant_id"]
	if tenantID == "" {
		t.Fatal("missing tenant_id")
	}

	keys := loadKeys(t)
	keyBody := map[string]string{
		"kid":        keys.KID,
		"alg":        keys.Alg,
		"public_key": keys.PublicKeyBase64,
	}
	body, _ := json.Marshal(keyBody)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tenants/"+tenantID+"/keys/signing", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", "secret")
	server.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestManifestNoRouteDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	env := loadEnvelope(t, "envelope_1.json")
	keys := loadKeys(t)
	pubKey := decodeBase64(t, keys.PublicKeyBase64)
	seed := decodeHex(t, keys.SeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)

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
	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       keys.KID,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}

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

	recordUC := &usecase.RecordSignedManifest{
		Keys:   keyRepo,
		Manif:  &memoryManifestRepo{},
		Log:    log,
		Crypto: cryptoSvc,
	}
	verifyUC := &usecase.VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  cryptoSvc,
		Merkle:  &merkle.Service{},
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Record: recordUC,
		Verify: verifyUC,
	})

	t.Run("record route", func(t *testing.T) {
		body := readVectorFile(t, "envelope_1.json")
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("verify route", func(t *testing.T) {
		proof := loadProofRequest(t)
		reqBody := verifyRequestRaw{
			Envelope: readVectorFile(t, "envelope_3.json"),
			Proof:    &proof,
		}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("extra segment 404", func(t *testing.T) {
		body := readVectorFile(t, "envelope_1.json")
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/manifests:record/extra", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("get not routed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/manifests:record", nil)
		server.r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 404/405, got %d", w.Code)
		}
	})
}

func TestLogEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	keys := loadKeys(t)
	log := logmem.New()
	ctx := context.Background()

	leaf1 := decodeHex(t, loadLeafHex(t, "leaf_1.sha256.hex"))
	leaf2 := decodeHex(t, loadLeafHex(t, "leaf_2.sha256.hex"))
	if _, _, _, err := log.AppendLeaf(ctx, keys.TenantID, "signed-1", leaf1); err != nil {
		t.Fatalf("append leaf1: %v", err)
	}
	if _, _, _, err := log.AppendLeaf(ctx, keys.TenantID, "signed-2", leaf2); err != nil {
		t.Fatalf("append leaf2: %v", err)
	}

	server := NewServerWithDeps(config.Config{}, ServerDeps{
		Log: log,
	})

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

func loadEnvelope(t *testing.T, name string) domain.SignedManifestEnvelope {
	t.Helper()
	var env domain.SignedManifestEnvelope
	data := readVectorFile(t, name)
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

func loadKeys(t *testing.T) keyVector {
	t.Helper()
	var keys keyVector
	data := readVectorFile(t, "keys.json")
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal keys: %v", err)
	}
	return keys
}

func loadLeafHex(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(string(readVectorFile(t, name)))
}

func loadProofRequest(t *testing.T) proofInput {
	t.Helper()
	var sth sthVector
	if err := json.Unmarshal(readVectorFile(t, "sth.json"), &sth); err != nil {
		t.Fatalf("unmarshal sth: %v", err)
	}
	var inclusion inclusionVector
	if err := json.Unmarshal(readVectorFile(t, "inclusion_proof_leaf_index_2.json"), &inclusion); err != nil {
		t.Fatalf("unmarshal inclusion: %v", err)
	}
	signature := strings.TrimSpace(string(readVectorFile(t, "sth.signature.b64")))
	return proofInput{
		STH: sthInput{
			TenantID:  sth.TenantID,
			TreeSize:  sth.TreeSize,
			RootHash:  sth.RootHash,
			IssuedAt:  sth.IssuedAt,
			Signature: signature,
		},
		Inclusion: inclusionInput{
			TenantID:    inclusion.TenantID,
			LeafIndex:   inclusion.LeafIndex,
			Path:        inclusion.Path,
			STHTreeSize: inclusion.STHTreeSize,
			STHRootHash: inclusion.STHRootHash,
		},
	}
}

func readVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testvectors", "v0", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return out
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func assertErrorCode(t *testing.T, body []byte, expected string) {
	t.Helper()
	var resp errorResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Code != expected {
		t.Fatalf("expected code %s, got %s", expected, resp.Code)
	}
}
