package usecase

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
)

func TestReplayBundle_EndToEnd(t *testing.T) {
	ctx := context.Background()
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
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

	logPrivKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
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

	recordUC := &RecordSignedManifest{
		Tenants: &noopTenantRepo{},
		Keys:    keyRepo,
		Manif:   &memoryManifestRepo{},
		Log:     log,
		Crypto:  cryptoSvc,
	}
	recordResp, err := recordUC.Execute(ctx, RecordSignedManifestRequest{Envelope: env})
	if err != nil {
		t.Fatalf("record signed manifest: %v", err)
	}
	if recordResp.STH == nil || recordResp.Inclusion == nil {
		t.Fatal("expected sth and inclusion proof")
	}
	if len(recordResp.STH.Signature) == 0 {
		t.Fatal("expected sth signature")
	}

	sthSigB64 := base64.StdEncoding.EncodeToString(recordResp.STH.Signature)
	proof := &ProofBundle{
		STH:          *recordResp.STH,
		STHSignature: sthSigB64,
		Inclusion:    *recordResp.Inclusion,
	}

	policyEngine, err := policyopa.NewEngineFromBundlePath(ctx, filepath.Join("..", "..", "policy", "bundles", "reference_v0"), "reference_v0")
	if err != nil {
		t.Fatalf("load policy bundle: %v", err)
	}

	verifyUC := &VerifySignedManifest{
		Keys:     keyRepo,
		LogKeys:  logKeyRepo,
		Crypto:   cryptoSvc,
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &DecisionEngineV0{},
	}

	receipt, err := verifyUC.Execute(ctx, VerifySignedManifestRequest{
		Envelope:     env,
		ProofBundle:  proof,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("verify signed manifest: %v", err)
	}
	if receipt.Policy == nil || receipt.Decision == nil {
		t.Fatal("expected policy and decision results")
	}

	policyEval := policyEvaluationFromReceipt(t, receipt.Policy)
	replayBundle, err := replay.BuildReplayBundle(replay.BundleInput{
		Envelope:         env,
		STH:              *receipt.STH,
		STHSignature:     sthSigB64,
		Inclusion:        *receipt.InclusionProof,
		PolicyEvaluation: &policyEval,
		DecisionResult:   receipt.Decision,
	})
	if err != nil {
		t.Fatalf("build replay bundle: %v", err)
	}
	if replayBundle.ReplayInputsDigest == "" {
		t.Fatal("expected replay inputs digest")
	}

	replayProof := proofBundleFromReplay(t, replayBundle)
	offlineReceipt, err := verifyUC.Execute(ctx, VerifySignedManifestRequest{
		Envelope:     replayBundle.Envelope,
		ProofBundle:  replayProof,
		RequireProof: true,
	})
	if err != nil {
		t.Fatalf("offline verify signed manifest: %v", err)
	}

	if !reflect.DeepEqual(receipt.Policy, offlineReceipt.Policy) {
		t.Fatalf("policy results mismatch")
	}
	if !reflect.DeepEqual(receipt.Decision, offlineReceipt.Decision) {
		t.Fatalf("decision results mismatch")
	}

	offlineEval := policyEvaluationFromReceipt(t, offlineReceipt.Policy)
	offlineBundle, err := replay.BuildReplayBundle(replay.BundleInput{
		Envelope:         replayBundle.Envelope,
		STH:              replayProof.STH,
		STHSignature:     replayProof.STHSignature,
		Inclusion:        replayProof.Inclusion,
		PolicyEvaluation: &offlineEval,
		DecisionResult:   offlineReceipt.Decision,
	})
	if err != nil {
		t.Fatalf("build offline replay bundle: %v", err)
	}
	if replayBundle.ReplayInputsDigest != offlineBundle.ReplayInputsDigest {
		t.Fatalf("replay inputs digest mismatch")
	}
}

func policyEvaluationFromReceipt(t *testing.T, receipt domain.PolicyReceipt) domain.PolicyEvaluation {
	t.Helper()
	if receipt == nil {
		t.Fatal("policy receipt is nil")
	}
	hash, ok := receipt["bundle_hash"].(string)
	if !ok || hash == "" {
		t.Fatal("policy bundle hash missing")
	}
	resultValue, ok := receipt["result"]
	if !ok {
		t.Fatal("policy result missing")
	}
	result, ok := resultValue.(domain.PolicyResult)
	if !ok {
		t.Fatalf("unexpected policy result type %T", resultValue)
	}
	eval := domain.PolicyEvaluation{
		BundleHash: hash,
		Result:     result,
	}
	if bundleID, ok := receipt["bundle_id"].(string); ok {
		eval.BundleID = bundleID
	}
	return eval
}

func proofBundleFromReplay(t *testing.T, bundle replay.ReplayBundle) *ProofBundle {
	t.Helper()
	sth := bundle.Proof.STH
	issuedAt, err := time.Parse(time.RFC3339, sth.IssuedAt)
	if err != nil {
		t.Fatalf("parse sth issued_at: %v", err)
	}
	inclusion := bundle.Proof.InclusionProof
	return &ProofBundle{
		STH: domain.STH{
			TenantID:  sth.TenantID,
			TreeSize:  sth.TreeSize,
			RootHash:  decodeHex(t, sth.RootHash),
			IssuedAt:  issuedAt,
			Signature: nil,
		},
		STHSignature: sth.Signature,
		Inclusion: domain.InclusionProof{
			TenantID:    inclusion.TenantID,
			LeafIndex:   inclusion.LeafIndex,
			Path:        decodeHexPath(t, inclusion.Path),
			STHTreeSize: inclusion.STHTreeSize,
			STHRootHash: decodeHex(t, inclusion.STHRootHash),
		},
	}
}
