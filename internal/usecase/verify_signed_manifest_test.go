package usecase

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/merkle"
	"proteus/internal/infra/policyopa"
)

type inclusionVector struct {
	LeafHash    string   `json:"leaf_hash"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHRootHash string   `json:"sth_root_hash"`
	STHTreeSize int64    `json:"sth_tree_size"`
	TenantID    string   `json:"tenant_id"`
}

type sthVector struct {
	IssuedAt string `json:"issued_at"`
	RootHash string `json:"root_hash"`
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
}

type staticLogKeyRepo struct {
	key domain.SigningKey
	err error
}

func (r *staticLogKeyRepo) GetActive(ctx context.Context, tenantID string) (*domain.SigningKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	return &r.key, nil
}

type staticPolicyEngine struct {
	eval      domain.PolicyEvaluation
	lastInput *domain.PolicyInput
}

func (e *staticPolicyEngine) Evaluate(ctx context.Context, input domain.PolicyInput) (domain.PolicyEvaluation, error) {
	e.lastInput = &input
	return e.eval, nil
}

type staticEpochRepo struct {
	epoch int64
	calls int
}

func (r *staticEpochRepo) GetEpoch(ctx context.Context, tenantID string) (int64, error) {
	r.calls++
	return r.epoch, nil
}

func (r *staticEpochRepo) BumpEpoch(ctx context.Context, tenantID string) (int64, error) {
	r.epoch++
	return r.epoch, nil
}

type sequenceEpochRepo struct {
	epochs []int64
	index  int
}

func (r *sequenceEpochRepo) GetEpoch(ctx context.Context, tenantID string) (int64, error) {
	if len(r.epochs) == 0 {
		return 0, nil
	}
	if r.index >= len(r.epochs) {
		return r.epochs[len(r.epochs)-1], nil
	}
	epoch := r.epochs[r.index]
	r.index++
	return epoch, nil
}

func (r *sequenceEpochRepo) BumpEpoch(ctx context.Context, tenantID string) (int64, error) {
	return r.GetEpoch(ctx, tenantID)
}

type trackingCache struct {
	mu      sync.Mutex
	entries map[string]domain.VerificationResult
	getKeys []string
	putKeys []string
}

func newTrackingCache() *trackingCache {
	return &trackingCache{
		entries: make(map[string]domain.VerificationResult),
	}
}

func (c *trackingCache) Get(ctx context.Context, key string) (*domain.VerificationResult, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getKeys = append(c.getKeys, key)
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
	c.putKeys = append(c.putKeys, key)
	c.entries[key] = value
	return nil
}

type revocationRepo struct {
	keyRepo *staticKeyRepo
}

func (r *revocationRepo) Revoke(ctx context.Context, rev domain.Revocation) error {
	if r.keyRepo == nil {
		return errors.New("key repo is nil")
	}
	if r.keyRepo.revoked == nil {
		r.keyRepo.revoked = make(map[string]bool)
	}
	r.keyRepo.revoked[rev.TenantID+":"+rev.KID] = true
	return nil
}

func TestVerifySignedManifest_OfflineProofBundle(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_3.json"))
	keys := loadKeys(t, filepath.Join(vectorsDir, "keys.json"))
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

	bundle := loadProofBundle(t, vectorsDir)
	expectedLeafHash := decodeHex(t, strings.TrimSpace(string(readFile(t, filepath.Join(vectorsDir, "leaf_3.sha256.hex")))))

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
	logKey := domain.SigningKey{
		TenantID:  env.Manifest.TenantID,
		KID:       env.Signature.KID,
		Purpose:   domain.KeyPurposeLog,
		Alg:       keys.Alg,
		PublicKey: pubKey,
		Status:    domain.KeyStatusActive,
	}

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: &staticLogKeyRepo{key: logKey},
		Log:     nil,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	resp, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}
	leafHash, err := uc.Crypto.ComputeLeafHash(env)
	if err != nil {
		t.Fatalf("compute leaf hash: %v", err)
	}
	if !bytes.Equal(leafHash, expectedLeafHash) {
		t.Fatal("leaf hash mismatch with test vector")
	}
	if resp.InclusionProof == nil || resp.STH == nil {
		t.Fatal("expected inclusion proof and sth")
	}
	if !resp.LogIncluded {
		t.Fatal("expected log included")
	}
}

func TestVerifySignedManifest_LogKeyPurposeMismatch(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_3.json"))
	keys := loadKeys(t, filepath.Join(vectorsDir, "keys.json"))
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

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
			KID:       env.Signature.KID,
			Purpose:   domain.KeyPurposeSigning,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}
	bundle := loadProofBundle(t, vectorsDir)

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrSTHInvalid) {
		t.Fatalf("expected sth invalid for purpose mismatch, got %v", err)
	}
}

func TestVerifySignedManifest_TamperedProofPath(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	bundle.Inclusion.Path[0][0] ^= 0x01

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrLogProofInvalid) {
		t.Fatalf("expected log proof invalid, got %v", err)
	}
}

func TestVerifySignedManifest_ModifiedSTHRoot(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	bundle.STH.RootHash[0] ^= 0x01

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrSTHInvalid) {
		t.Fatalf("expected sth invalid, got %v", err)
	}
}

func TestVerifySignedManifest_WrongSignature(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	env.Signature.Value = "not-base64"

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrSignatureInvalid) {
		t.Fatalf("expected signature invalid, got %v", err)
	}
}

func TestVerifySignedManifest_RevokedKey(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	keyRepo.revoked[env.Manifest.TenantID+":"+env.Signature.KID] = true

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrKeyRevoked) {
		t.Fatalf("expected key revoked, got %v", err)
	}
}

func TestVerifySignedManifest_AttachesPolicyResult(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	policyEngine := &staticPolicyEngine{
		eval: domain.PolicyEvaluation{
			BundleID:   "reference_v0",
			BundleHash: "bundlehash",
			Result: domain.PolicyResult{
				Allow: true,
			},
		},
	}
	epochRepo := &staticEpochRepo{epoch: 7}

	uc := &VerifySignedManifest{
		Keys:             keyRepo,
		LogKeys:          logKeyRepo,
		Crypto:           &crypto.Service{},
		Merkle:           &merkle.Service{},
		Policy:           policyEngine,
		Decision:         &DecisionEngineV0{},
		RevocationEpochs: epochRepo,
	}

	resp, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}
	if resp.Policy == nil {
		t.Fatalf("expected policy result in receipt")
	}
	if resp.Policy["bundle_hash"] != "bundlehash" {
		t.Fatalf("expected bundle_hash in policy receipt")
	}
	if resp.Policy["bundle_id"] != "reference_v0" {
		t.Fatalf("expected bundle_id in policy receipt")
	}
	if policyEngine.lastInput == nil || policyEngine.lastInput.Options == nil || !policyEngine.lastInput.Options.RequireProof {
		t.Fatalf("expected policy input to include require_proof")
	}
	if policyEngine.lastInput.RevocationEpoch != epochRepo.epoch {
		t.Fatalf("expected revocation_epoch %d, got %d", epochRepo.epoch, policyEngine.lastInput.RevocationEpoch)
	}
	if resp.Decision == nil {
		t.Fatalf("expected decision result in receipt")
	}
	if resp.Decision["engine_version"] == "" {
		t.Fatalf("expected decision engine version")
	}
	if resp.Decision["action"] != "allow" {
		t.Fatalf("expected decision action allow")
	}
}

func TestVerifySignedManifest_CacheKeyIncludesRevocationEpoch(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	cache := newTrackingCache()
	epochRepo := &sequenceEpochRepo{epochs: []int64{0, 1}}

	uc := &VerifySignedManifest{
		Keys:             keyRepo,
		LogKeys:          logKeyRepo,
		Crypto:           &crypto.Service{},
		Merkle:           &merkle.Service{},
		RevocationEpochs: epochRepo,
		Cache:            cache,
	}

	first, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest (first): %v", err)
	}
	leafHash, err := uc.Crypto.ComputeLeafHash(env)
	if err != nil {
		t.Fatalf("compute leaf hash: %v", err)
	}
	keyEpoch0 := verificationCacheKey(env.Manifest.TenantID, leafHash, &bundle.STH, 0)
	if _, ok := cache.entries[keyEpoch0]; !ok {
		t.Fatalf("expected cache entry for epoch 0")
	}

	second, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest (second): %v", err)
	}
	if first.RevocationEpoch == second.RevocationEpoch {
		t.Fatalf("expected revocation epoch to change between calls")
	}
	keyEpoch1 := verificationCacheKey(env.Manifest.TenantID, leafHash, &bundle.STH, 1)
	if _, ok := cache.entries[keyEpoch1]; !ok {
		t.Fatalf("expected cache entry for epoch 1")
	}
}

func TestVerifySignedManifest_RevocationCausesDeterministicFailure(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	epochRepo := &staticEpochRepo{epoch: 0}
	revSvc := NewRevocationService(&revocationRepo{keyRepo: keyRepo}, epochRepo)

	uc := &VerifySignedManifest{
		Keys:             keyRepo,
		LogKeys:          logKeyRepo,
		Crypto:           &crypto.Service{},
		Merkle:           &merkle.Service{},
		RevocationEpochs: epochRepo,
	}

	first, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest (first): %v", err)
	}
	if first.KeyStatus != string(domain.KeyStatusActive) {
		t.Fatalf("expected key status active, got %s", first.KeyStatus)
	}

	if _, err := revSvc.Revoke(context.Background(), domain.Revocation{TenantID: env.Manifest.TenantID, KID: env.Signature.KID}); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	_, err = uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if !errors.Is(err, domain.ErrKeyRevoked) {
		t.Fatalf("expected key revoked, got %v", err)
	}
}

func TestPolicyDecision_DenyWhenKeyRevoked(t *testing.T) {
	env, _, _, _ := setupVerifyUsecase(t)
	policyEngine, err := policyopa.NewEngineFromBundlePath(context.Background(), filepath.Join("..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}

	verification := domain.PolicyVerification{
		SignatureValid: true,
		KeyStatus:      string(domain.KeyStatusRevoked),
		LogIncluded:    true,
	}
	policyEval, err := policyEngine.Evaluate(context.Background(), domain.PolicyInput{
		Envelope:        env,
		Verification:    verification,
		Options:         &domain.PolicyOptions{RequireProof: true},
		RevocationEpoch: 1,
	})
	if err != nil {
		t.Fatalf("policy evaluate: %v", err)
	}
	if policyEval.Result.Allow {
		t.Fatalf("expected policy deny for revoked key")
	}

	decision, err := (&DecisionEngineV0{}).Evaluate(DecisionInput{
		Verification:    verification,
		Policy:          policyEval.Result,
		RevocationEpoch: 1,
	})
	if err != nil {
		t.Fatalf("decision evaluate: %v", err)
	}
	if decision.Action != "block" {
		t.Fatalf("expected decision block, got %s", decision.Action)
	}
}

func TestVerifySignedManifest_DisablesCacheWithoutEpochRepo(t *testing.T) {
	env, bundle, keyRepo, logKeyRepo := setupVerifyUsecase(t)
	cache := newTrackingCache()

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
		Cache:   cache,
	}

	_, err := uc.Execute(context.Background(), VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  bundle,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}
	if len(cache.entries) != 0 {
		t.Fatalf("expected cache disabled when revocation epochs are nil")
	}
}

func setupVerifyUsecase(t *testing.T) (domain.SignedManifestEnvelope, *ProofBundle, *staticKeyRepo, *staticLogKeyRepo) {
	t.Helper()
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_3.json"))
	keys := loadKeys(t, filepath.Join(vectorsDir, "keys.json"))
	pubKey := decodeBase64(t, keys.PublicKeyBase64)

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

	logRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       env.Signature.KID,
			Purpose:   domain.KeyPurposeLog,
			Alg:       keys.Alg,
			PublicKey: pubKey,
			Status:    domain.KeyStatusActive,
		},
	}

	bundle := loadProofBundle(t, vectorsDir)
	return env, bundle, keyRepo, logRepo
}

func loadProofBundle(t *testing.T, vectorsDir string) *ProofBundle {
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

	return &ProofBundle{
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
