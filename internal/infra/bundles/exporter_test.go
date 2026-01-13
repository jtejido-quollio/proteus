package bundles

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/infra/policyopa"
	"proteus/internal/infra/replay"
	"proteus/internal/usecase"
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

type memoryManifestRepo struct{}

func (r *memoryManifestRepo) UpsertManifestAndEnvelope(ctx context.Context, env domain.SignedManifestEnvelope) (string, string, error) {
	return env.Manifest.ManifestID, "signed-id", nil
}

type noopTenantRepo struct{}

func (r *noopTenantRepo) GetByID(ctx context.Context, tenantID string) (*domain.Tenant, error) {
	return nil, domain.ErrNotFound
}

func (r *noopTenantRepo) Create(ctx context.Context, tenant domain.Tenant) error {
	return domain.ErrNotFound
}

func TestEvidenceBundleExport_Deterministic(t *testing.T) {
	input := buildBundleInput(t)
	first, err := ExportJSON(input)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	second, err := ExportJSON(input)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("expected deterministic bundle output")
	}
}

func TestEvidenceBundleExport_Replayable(t *testing.T) {
	input := buildBundleInput(t)
	payload, err := ExportJSON(input)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}

	var bundle EvidenceBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal evidence bundle: %v", err)
	}
	if bundle.ReceiptDigest == "" || bundle.ReplayInputsDigest == "" {
		t.Fatalf("expected digests in bundle")
	}
	cryptoSvc := &crypto.Service{}
	origCanon, err := cryptoSvc.CanonicalizeManifest(input.Envelopes[0].Manifest)
	if err != nil {
		t.Fatalf("canonicalize original manifest: %v", err)
	}
	bundleEnv := bundle.Envelopes[0].ToDomain()
	bundleCanon, err := cryptoSvc.CanonicalizeManifest(bundleEnv.Manifest)
	if err != nil {
		t.Fatalf("canonicalize bundle manifest: %v", err)
	}
	if !bytes.Equal(origCanon, bundleCanon) {
		t.Fatalf("manifest canonical bytes changed after bundle roundtrip")
	}

	recomputedReceiptDigest := computeReceiptDigestForTest(t, bundle.Receipt)
	if recomputedReceiptDigest != bundle.ReceiptDigest {
		t.Fatalf("receipt digest mismatch")
	}

	offlineReceipt := verifyOffline(t, bundle)
	bundleEval, err := policyEvaluationFromReceipt(bundle.Receipt.Policy)
	if err != nil {
		t.Fatalf("policy eval from bundle: %v", err)
	}
	offlineEval, err := policyEvaluationFromReceipt(offlineReceipt.Policy)
	if err != nil {
		t.Fatalf("policy eval from offline receipt: %v", err)
	}
	bundleEval = normalizePolicyEval(bundleEval)
	offlineEval = normalizePolicyEval(offlineEval)
	if !reflect.DeepEqual(bundleEval, offlineEval) {
		t.Fatalf("policy mismatch in offline verification: bundle=%+v offline=%+v", bundleEval, offlineEval)
	}
	bundleDecision, err := decisionFromReceipt(bundle.Receipt.Decision)
	if err != nil {
		t.Fatalf("decision from bundle: %v", err)
	}
	offlineDecision, err := decisionFromReceipt(offlineReceipt.Decision)
	if err != nil {
		t.Fatalf("decision from offline receipt: %v", err)
	}
	if !reflect.DeepEqual(bundleDecision, offlineDecision) {
		t.Fatalf("decision mismatch in offline verification")
	}

	replayDigest := computeReplayDigestFromOffline(t, bundle, offlineReceipt)
	if replayDigest != bundle.ReplayInputsDigest {
		t.Fatalf("replay inputs digest mismatch")
	}
}

func buildBundleInput(t *testing.T) BundleInput {
	t.Helper()
	ctx := context.Background()
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_1.json"))
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

	logPrivKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	logPubKey := logPrivKey.Public().(ed25519.PublicKey)
	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       "log-key-1",
			Alg:       "ed25519",
			PublicKey: logPubKey,
			Status:    domain.KeyStatusActive,
		},
	}

	cryptoSvc := &crypto.Service{}
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	signSTH := func(sth domain.STH) ([]byte, error) {
		canonical, err := cryptoSvc.CanonicalizeSTH(sth)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(logPrivKey, canonical), nil
	}
	log := logmem.NewWithSignerAndClock(signSTH, func() time.Time { return fixedTime })

	recordUC := &usecase.RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     log,
		Crypto:  cryptoSvc,
	}
	recordResp, err := recordUC.Execute(ctx, usecase.RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("record signed manifest: %v", err)
	}

	policyEngine, err := policyopa.NewEngineFromBundlePath(ctx, filepath.Join("..", "..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}

	verifyUC := &usecase.VerifySignedManifest{
		Keys:     keyRepo,
		LogKeys:  logKeyRepo,
		Crypto:   cryptoSvc,
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &usecase.DecisionEngineV0{},
	}
	sthSigB64 := base64.StdEncoding.EncodeToString(recordResp.STH.Signature)
	receipt, err := verifyUC.Execute(ctx, usecase.VerifySignedManifestRequest{
		Envelope: env,
		ProofBundle: &usecase.ProofBundle{
			STH:          *recordResp.STH,
			STHSignature: sthSigB64,
			Inclusion:    *recordResp.Inclusion,
		},
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}

	receiptPayload := receiptFromVerify(receipt)
	policyEval, err := policyEvaluationFromReceipt(receiptPayload.Policy)
	if err != nil {
		t.Fatalf("policy eval from receipt: %v", err)
	}

	return BundleInput{
		BundleID:   "bundle-1",
		Envelopes:  []domain.SignedManifestEnvelope{env},
		Proofs: []ProofInput{
			{
				STH:          *recordResp.STH,
				STHSignature: sthSigB64,
				Inclusion:    *recordResp.Inclusion,
			},
		},
		Receipt:          receiptPayload,
		PolicyEvaluation: &policyEval,
		Decision:         receiptPayload.Decision,
		Engines: replay.EngineVersions{
			Verification: replay.DefaultVerificationEngineVersion,
			Policy:       replay.DefaultPolicyEngineVersion,
			Decision:     replay.DefaultDecisionEngineVersion,
		},
		SigningKeys: []domain.SigningKey{keyRepo.keys[env.Manifest.TenantID+":"+env.Signature.KID]},
		LogKeys:     []domain.SigningKey{logKeyRepo.key},
	}
}

func receiptFromVerify(receipt *usecase.VerifyReceipt) Receipt {
	out := Receipt{
		SignatureValid:      receipt.SignatureValid,
		KeyStatus:           receipt.KeyStatus,
		RevocationCheckedAt: receipt.RevocationCheckedAt,
		LogIncluded:         receipt.LogIncluded,
		SubjectHash:         receipt.SubjectHash,
		ManifestID:          receipt.ManifestID,
		TenantID:            receipt.TenantID,
		Derivation:          receipt.Derivation,
		Policy:              receipt.Policy,
		Decision:            receipt.Decision,
		Replay:              receipt.Replay,
	}
	if receipt.STH != nil {
		sig := ""
		if len(receipt.STH.Signature) > 0 {
			sig = base64.StdEncoding.EncodeToString(receipt.STH.Signature)
		}
		sth := buildSTHEntry(*receipt.STH, sig)
		out.STH = &sth
	}
	if receipt.InclusionProof != nil {
		inclusion := buildInclusionEntry(*receipt.InclusionProof)
		out.InclusionProof = &inclusion
	}
	if receipt.Consistency != nil {
		consistency := buildConsistencyEntry(*receipt.Consistency)
		out.ConsistencyProof = &consistency
	}
	return out
}

func computeReceiptDigestForTest(t *testing.T, receipt Receipt) string {
	t.Helper()
	canonical, err := crypto.CanonicalizeAny(receipt)
	if err != nil {
		t.Fatalf("canonicalize receipt: %v", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func computeReplayDigestFromOffline(t *testing.T, bundle EvidenceBundle, receipt *usecase.VerifyReceipt) string {
	t.Helper()
	if len(bundle.Envelopes) == 0 || len(bundle.Proofs.STHs) == 0 || len(bundle.Proofs.InclusionProofs) == 0 {
		t.Fatalf("bundle missing envelope or proofs")
	}
	sth := bundle.Proofs.STHs[0]
	inclusion := bundle.Proofs.InclusionProofs[0]
	issuedAt, err := time.Parse(time.RFC3339, sth.IssuedAt)
	if err != nil {
		t.Fatalf("parse sth issued_at: %v", err)
	}
	input := BundleInput{
		BundleID:  bundle.BundleID,
		Envelopes: []domain.SignedManifestEnvelope{bundle.Envelopes[0].ToDomain()},
		Proofs: []ProofInput{
			{
				STH: domain.STH{
					TenantID:  sth.TenantID,
					TreeSize:  sth.TreeSize,
					RootHash:  decodeHex(t, sth.RootHash),
					IssuedAt:  issuedAt,
				},
				STHSignature: sth.Signature,
				Inclusion: domain.InclusionProof{
					TenantID:    inclusion.TenantID,
					LeafIndex:   inclusion.LeafIndex,
					Path:        decodeHexPath(t, inclusion.Path),
					STHTreeSize: inclusion.STHTreeSize,
					STHRootHash: decodeHex(t, inclusion.STHRootHash),
				},
			},
		},
		Receipt: receiptFromVerify(receipt),
		Engines: bundle.Engines,
	}
	digest, err := computeReplayInputsDigest(input, input.Receipt)
	if err != nil {
		t.Fatalf("compute replay digest: %v", err)
	}
	return digest
}

type decisionPayload struct {
	EngineVersion string   `json:"engine_version"`
	Action        string   `json:"action"`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons,omitempty"`
}

func decisionFromReceipt(receipt domain.DecisionReceipt) (decisionPayload, error) {
	if receipt == nil {
		return decisionPayload{}, errors.New("decision receipt is required")
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return decisionPayload{}, err
	}
	var out decisionPayload
	if err := json.Unmarshal(payload, &out); err != nil {
		return decisionPayload{}, err
	}
	return out, nil
}

func normalizePolicyEval(eval domain.PolicyEvaluation) domain.PolicyEvaluation {
	if len(eval.Result.Deny) == 0 {
		eval.Result.Deny = nil
	}
	return eval
}

func verifyOffline(t *testing.T, bundle EvidenceBundle) *usecase.VerifyReceipt {
	t.Helper()
	env := bundle.Envelopes[0].ToDomain()
	if len(bundle.Keys.Signing) == 0 {
		t.Fatalf("bundle missing signing keys")
	}
	signingKey := bundle.Keys.Signing[0]
	pubKey := decodeBase64(t, signingKey.PublicKeyBase64)

	keyRepo := &staticKeyRepo{
		keys: map[string]domain.SigningKey{
			env.Manifest.TenantID + ":" + env.Signature.KID: {
				TenantID:  env.Manifest.TenantID,
				KID:       env.Signature.KID,
				Alg:       signingKey.Alg,
				PublicKey: pubKey,
				Status:    domain.KeyStatusActive,
			},
		},
		revoked: map[string]bool{},
	}

	logKey := bundle.Keys.Log[0]
	logKeyRepo := &staticLogKeyRepo{
		key: domain.SigningKey{
			TenantID:  env.Manifest.TenantID,
			KID:       logKey.KID,
			Alg:       logKey.Alg,
			PublicKey: decodeBase64(t, logKey.PublicKeyBase64),
			Status:    domain.KeyStatusActive,
		},
	}

	policyEngine, err := policyopa.NewEngineFromBundlePath(context.Background(), filepath.Join("..", "..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}

	verifyUC := &usecase.VerifySignedManifest{
		Keys:     keyRepo,
		LogKeys:  logKeyRepo,
		Crypto:   &crypto.Service{},
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &usecase.DecisionEngineV0{},
	}
	sth := bundle.Proofs.STHs[0]
	inclusion := bundle.Proofs.InclusionProofs[0]
	issuedAt, err := time.Parse(time.RFC3339, sth.IssuedAt)
	if err != nil {
		t.Fatalf("parse sth issued_at: %v", err)
	}
	resp, err := verifyUC.Execute(context.Background(), usecase.VerifySignedManifestRequest{
		Envelope: env,
		ProofBundle: &usecase.ProofBundle{
			STH: domain.STH{
				TenantID:  sth.TenantID,
				TreeSize:  sth.TreeSize,
				RootHash:  decodeHex(t, sth.RootHash),
				IssuedAt:  issuedAt,
			},
			STHSignature: sth.Signature,
			Inclusion: domain.InclusionProof{
				TenantID:    inclusion.TenantID,
				LeafIndex:   inclusion.LeafIndex,
				Path:        decodeHexPath(t, inclusion.Path),
				STHTreeSize: inclusion.STHTreeSize,
				STHRootHash: decodeHex(t, inclusion.STHRootHash),
			},
		},
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	return resp
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
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return out
}

type keyVector struct {
	Alg             string `json:"alg"`
	KID             string `json:"kid"`
	PublicKeyBase64 string `json:"public_key_base64"`
	TenantID        string `json:"tenant_id"`
}
