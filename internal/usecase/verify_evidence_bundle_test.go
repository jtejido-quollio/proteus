package usecase

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/bundles"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/logmem"
	"proteus/internal/infra/merkle"
	"proteus/internal/infra/policyopa"
)

func TestVerifyEvidenceBundle_Pass(t *testing.T) {
	bundle := buildEvidenceBundle(t)
	verifier := buildEvidenceVerifier(t)

	result, err := verifier.Execute(context.Background(), bundle)
	if err != nil {
		t.Fatalf("verify evidence bundle: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got failures %v", result.Failures)
	}
}

func TestVerifyEvidenceBundle_BitFlipProof(t *testing.T) {
	bundle := buildEvidenceBundle(t)
	if len(bundle.Proofs.InclusionProofs) == 0 || len(bundle.Proofs.InclusionProofs[0].Path) == 0 {
		t.Fatal("bundle missing inclusion proof path")
	}
	bundle.Proofs.InclusionProofs[0].Path[0] = flipHex(bundle.Proofs.InclusionProofs[0].Path[0])

	verifier := buildEvidenceVerifier(t)
	result, err := verifier.Execute(context.Background(), bundle)
	if err != nil {
		t.Fatalf("verify evidence bundle: %v", err)
	}
	if !containsFailure(result.Failures, EvidenceFailLogProofInvalid) {
		t.Fatalf("expected failure %s, got %v", EvidenceFailLogProofInvalid, result.Failures)
	}
}

func TestVerifyEvidenceBundle_ModifiedPolicyHash(t *testing.T) {
	bundle := buildEvidenceBundle(t)
	if bundle.Receipt.Policy == nil {
		t.Fatal("bundle missing policy receipt")
	}
	bundle.Receipt.Policy["bundle_hash"] = "deadbeef"

	verifier := buildEvidenceVerifier(t)
	result, err := verifier.Execute(context.Background(), bundle)
	if err != nil {
		t.Fatalf("verify evidence bundle: %v", err)
	}
	if !containsFailure(result.Failures, EvidenceFailPolicyBundleHashMismatch) {
		t.Fatalf("expected failure %s, got %v", EvidenceFailPolicyBundleHashMismatch, result.Failures)
	}
}

func TestVerifyEvidenceBundle_ModifiedReceipt(t *testing.T) {
	bundle := buildEvidenceBundle(t)
	bundle.Receipt.ManifestID = "tampered"

	verifier := buildEvidenceVerifier(t)
	result, err := verifier.Execute(context.Background(), bundle)
	if err != nil {
		t.Fatalf("verify evidence bundle: %v", err)
	}
	if !containsFailure(result.Failures, EvidenceFailReceiptDigestMismatch) {
		t.Fatalf("expected failure %s, got %v", EvidenceFailReceiptDigestMismatch, result.Failures)
	}
}

func buildEvidenceVerifier(t *testing.T) *VerifyEvidenceBundle {
	t.Helper()
	policyEngine, err := policyopa.NewEngineFromBundlePath(context.Background(), filepath.Join("..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}
	return &VerifyEvidenceBundle{
		Crypto:   &crypto.Service{},
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &DecisionEngineV0{},
	}
}

func buildEvidenceBundle(t *testing.T) EvidenceBundle {
	t.Helper()
	payload := buildEvidenceBundleJSON(t)
	var bundle EvidenceBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal evidence bundle: %v", err)
	}
	return bundle
}

func buildEvidenceBundleJSON(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	env1 := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_1.json"))
	env := loadEnvelope(t, filepath.Join(vectorsDir, "envelope_2.json"))
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

	logPrivKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	logPubKey := logPrivKey.Public().(ed25519.PublicKey)
	logKey := domain.SigningKey{
		TenantID:  env.Manifest.TenantID,
		KID:       "log-key-1",
		Alg:       "ed25519",
		PublicKey: logPubKey,
		Status:    domain.KeyStatusActive,
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

	recordUC := &RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     log,
		Crypto:  cryptoSvc,
	}
	if _, err := recordUC.Execute(ctx, RecordSignedManifestRequest{Envelope: env1}); err != nil {
		t.Fatalf("record signed manifest (seed): %v", err)
	}
	recordResp, err := recordUC.Execute(ctx, RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("record signed manifest: %v", err)
	}

	policyEngine, err := policyopa.NewEngineFromBundlePath(ctx, filepath.Join("..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}
	verifyUC := &VerifySignedManifest{
		Keys:     keyRepo,
		LogKeys:  &staticLogKeyRepo{key: logKey},
		Crypto:   cryptoSvc,
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &DecisionEngineV0{},
	}
	sthSigB64 := base64.StdEncoding.EncodeToString(recordResp.STH.Signature)
	receipt, err := verifyUC.Execute(ctx, VerifySignedManifestRequest{
		Envelope: env,
		ProofBundle: &ProofBundle{
			STH:          *recordResp.STH,
			STHSignature: sthSigB64,
			Inclusion:    *recordResp.Inclusion,
		},
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}

	policyEval := policyEvaluationFromReceipt(t, receipt.Policy)

	input := bundles.BundleInput{
		BundleID:   "bundle-1",
		Envelopes:  []domain.SignedManifestEnvelope{env},
		Proofs: []bundles.ProofInput{
			{
				STH:          *recordResp.STH,
				STHSignature: sthSigB64,
				Inclusion:    *recordResp.Inclusion,
			},
		},
		Receipt:          receiptToBundle(receipt),
		PolicyEvaluation: &policyEval,
		Decision:         receipt.Decision,
		SigningKeys:      []domain.SigningKey{keyRepo.keys[env.Manifest.TenantID+":"+env.Signature.KID]},
		LogKeys:          []domain.SigningKey{logKey},
	}

	payload, err := bundles.ExportJSON(input)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	return payload
}

func receiptToBundle(receipt *VerifyReceipt) bundles.Receipt {
	out := bundles.Receipt{
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
		sth := bundles.STHEntry{
			TenantID:  receipt.STH.TenantID,
			TreeSize:  receipt.STH.TreeSize,
			RootHash:  hex.EncodeToString(receipt.STH.RootHash),
			IssuedAt:  receipt.STH.IssuedAt.UTC().Format(time.RFC3339),
			Signature: sig,
		}
		out.STH = &sth
	}
	if receipt.InclusionProof != nil {
		out.InclusionProof = &bundles.InclusionEntry{
			TenantID:    receipt.InclusionProof.TenantID,
			LeafIndex:   receipt.InclusionProof.LeafIndex,
			Path:        encodeHexPath(receipt.InclusionProof.Path),
			STHTreeSize: receipt.InclusionProof.STHTreeSize,
			STHRootHash: hex.EncodeToString(receipt.InclusionProof.STHRootHash),
		}
	}
	if receipt.Consistency != nil {
		out.ConsistencyProof = &bundles.ConsistencyEntry{
			TenantID: receipt.Consistency.TenantID,
			FromSize: receipt.Consistency.FromSize,
			ToSize:   receipt.Consistency.ToSize,
			Path:     encodeHexPath(receipt.Consistency.Path),
		}
	}
	return out
}

func encodeHexPath(path [][]byte) []string {
	out := make([]string, 0, len(path))
	for _, node := range path {
		out = append(out, hex.EncodeToString(node))
	}
	return out
}

func flipHex(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	last := value[len(value)-1]
	switch last {
	case '0':
		last = '1'
	default:
		last = '0'
	}
	return value[:len(value)-1] + string(last)
}

func containsFailure(failures []string, code string) bool {
	for _, failure := range failures {
		if failure == code {
			return true
		}
	}
	return false
}
