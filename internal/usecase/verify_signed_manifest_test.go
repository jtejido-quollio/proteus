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
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/merkle"
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
				Alg:       keys.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: &staticLogKeyRepo{key: keyRepo.keys[env.Manifest.TenantID+":"+env.Signature.KID]},
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

	uc := &VerifySignedManifest{
		Keys:    keyRepo,
		LogKeys: logKeyRepo,
		Crypto:  &crypto.Service{},
		Merkle:  &merkle.Service{},
		Policy:  policyEngine,
		Decision: &DecisionEngineV0{},
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
				Alg:       keys.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}

	logRepo := &staticLogKeyRepo{
		key: keyRepo.keys[env.Manifest.TenantID+":"+env.Signature.KID],
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
