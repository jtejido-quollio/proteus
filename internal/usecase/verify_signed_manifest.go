package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"proteus/internal/domain"
)

type VerifySignedManifestRequest struct {
	Envelope          domain.SignedManifestEnvelope
	Artifact          []byte
	ArtifactMediaType string
	ProofBundle       *ProofBundle
	RequireProof      bool
}

type VerifyReceipt struct {
	SignatureValid      bool
	KeyStatus           string
	RevocationCheckedAt string
	LogIncluded         bool
	SubjectHash         domain.Hash
	ManifestID          string
	TenantID            string
	RevocationEpoch     int64

	STH            *domain.STH
	InclusionProof *domain.InclusionProof
	Consistency    *domain.ConsistencyProof

	Derivation domain.DerivationReceipt
	Policy     domain.PolicyReceipt
	Decision   domain.DecisionReceipt
	Replay     domain.ReplayReceipt
}

type ProofBundle struct {
	STH          domain.STH
	STHSignature string
	Inclusion    domain.InclusionProof
}

type VerifySignedManifest struct {
	Keys             KeyRepository
	LogKeys          LogKeyRepository
	Log              TenantLog
	Crypto           CryptoService
	Merkle           MerkleService
	Policy           PolicyEngine
	Derivation       DerivationService
	Decision         DecisionEngine
	KeyManager       domain.KeyManager
	RevocationEpochs RevocationEpochRepository
	Cache            VerificationCache
	CacheTTL         time.Duration
}

func (uc *VerifySignedManifest) Execute(ctx context.Context, req VerifySignedManifestRequest) (*VerifyReceipt, error) {
	env := req.Envelope
	if err := validateManifest(env.Manifest); err != nil {
		return nil, err
	}
	if env.Signature.KID == "" || env.Signature.Value == "" {
		return nil, domain.ErrInvalidManifest
	}
	if env.Signature.Alg != "ed25519" {
		return nil, domain.ErrInvalidManifest
	}

	key, err := uc.Keys.GetByKID(ctx, env.Manifest.TenantID, env.Signature.KID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrKeyUnknown
		}
		return nil, err
	}
	if key.Purpose != domain.KeyPurposeSigning {
		return nil, domain.ErrKeyUnknown
	}

	epoch := int64(0)
	if uc.RevocationEpochs != nil {
		revEpoch, err := uc.RevocationEpochs.GetEpoch(ctx, env.Manifest.TenantID)
		if err != nil {
			return nil, err
		}
		epoch = revEpoch
	}
	cacheEnabled := uc.Cache != nil && uc.RevocationEpochs != nil

	revoked, err := uc.Keys.IsRevoked(ctx, env.Manifest.TenantID, env.Signature.KID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, domain.ErrKeyRevoked
	}

	canonical, err := uc.Crypto.CanonicalizeManifest(env.Manifest)
	if err != nil {
		return nil, err
	}
	if uc.KeyManager != nil {
		sigBytes, err := base64.StdEncoding.DecodeString(env.Signature.Value)
		if err != nil {
			return nil, domain.ErrSignatureInvalid
		}
		if err := uc.KeyManager.Verify(ctx, domain.KeyRef{
			TenantID: env.Manifest.TenantID,
			Purpose:  domain.KeyPurposeSigning,
			KID:      env.Signature.KID,
		}, canonical, sigBytes, key.PublicKey); err != nil {
			return nil, domain.ErrSignatureInvalid
		}
	} else {
		if err := uc.Crypto.VerifySignature(canonical, env.Signature, key.PublicKey); err != nil {
			return nil, domain.ErrSignatureInvalid
		}
	}

	leafHash, err := uc.Crypto.ComputeLeafHash(env)
	if err != nil {
		return nil, err
	}

	var cachedKey string
	if cacheEnabled && req.ProofBundle != nil && len(req.Artifact) == 0 {
		cachedKey = verificationCacheKey(env.Manifest.TenantID, leafHash, &req.ProofBundle.STH, epoch)
		if cachedKey != "" {
			if cached, ok, err := uc.Cache.Get(ctx, cachedKey); err == nil && ok && cached != nil {
				return receiptFromCache(cached), nil
			}
		}
	}

	var artifactHashValid *bool
	if len(req.Artifact) > 0 {
		mediaType := req.ArtifactMediaType
		if mediaType == "" {
			mediaType = env.Manifest.Subject.MediaType
		}
		alg, digest, err := uc.Crypto.CanonicalizeAndHashArtifact(mediaType, req.Artifact)
		if err != nil {
			return nil, err
		}
		if alg != env.Manifest.Subject.Hash.Alg || !stringsEqualFoldHex(digest, env.Manifest.Subject.Hash.Value) {
			return nil, domain.ErrArtifactHashMismatch
		}
		valid := true
		artifactHashValid = &valid
	}

	receipt := &VerifyReceipt{
		SignatureValid:      true,
		KeyStatus:           string(key.Status),
		RevocationCheckedAt: time.Now().UTC().Format(time.RFC3339),
		LogIncluded:         false,
		SubjectHash:         env.Manifest.Subject.Hash,
		ManifestID:          env.Manifest.ManifestID,
		TenantID:            env.Manifest.TenantID,
		RevocationEpoch:     epoch,
	}

	if req.ProofBundle != nil {
		if err := uc.verifyProofBundle(ctx, req.ProofBundle, env.Manifest.TenantID, leafHash); err != nil {
			return nil, err
		}
		receipt.LogIncluded = true
		receipt.STH = &req.ProofBundle.STH
		receipt.InclusionProof = &req.ProofBundle.Inclusion
		derivationSummary, err := uc.attachDerivation(ctx, receipt, env)
		if err != nil {
			return nil, err
		}
		verification := buildPolicyVerification(receipt, artifactHashValid)
		policyEval, err := uc.attachPolicy(ctx, receipt, env, verification, req.RequireProof)
		if err != nil {
			return nil, err
		}
		if err := uc.attachDecision(receipt, policyEval, derivationSummary, verification); err != nil {
			return nil, err
		}
		if cacheEnabled {
			uc.storeCache(ctx, cachedKey, receipt)
		}
		return receipt, nil
	}

	if req.RequireProof {
		return nil, domain.ErrProofRequired
	}

	if uc.Log == nil {
		return nil, domain.ErrNotFound
	}
	_, sth, inclusion, err := uc.Log.GetInclusionProof(ctx, env.Manifest.TenantID, leafHash)
	if err != nil {
		return nil, err
	}
	receipt.LogIncluded = true
	receipt.STH = &sth
	receipt.InclusionProof = &inclusion
	derivationSummary, err := uc.attachDerivation(ctx, receipt, env)
	if err != nil {
		return nil, err
	}
	verification := buildPolicyVerification(receipt, artifactHashValid)
	policyEval, err := uc.attachPolicy(ctx, receipt, env, verification, req.RequireProof)
	if err != nil {
		return nil, err
	}
	if err := uc.attachDecision(receipt, policyEval, derivationSummary, verification); err != nil {
		return nil, err
	}
	if cacheEnabled {
		uc.storeCache(ctx, verificationCacheKey(env.Manifest.TenantID, leafHash, receipt.STH, epoch), receipt)
	}
	return receipt, nil
}

func (uc *VerifySignedManifest) verifyProofBundle(ctx context.Context, bundle *ProofBundle, tenantID string, leafHash []byte) error {
	if bundle == nil {
		return domain.ErrLogProofInvalid
	}
	if uc.Merkle == nil {
		return domain.ErrLogProofInvalid
	}
	if bundle.STHSignature == "" {
		return domain.ErrSTHInvalid
	}
	if uc.LogKeys == nil {
		return domain.ErrSTHInvalid
	}
	logKey, err := uc.LogKeys.GetActive(ctx, tenantID)
	if err != nil {
		return domain.ErrSTHInvalid
	}
	if logKey.Purpose != domain.KeyPurposeLog {
		return domain.ErrSTHInvalid
	}
	if err := uc.Crypto.VerifySTHSignature(bundle.STH, bundle.STHSignature, logKey.PublicKey); err != nil {
		return domain.ErrSTHInvalid
	}

	if bundle.STH.TenantID != "" && bundle.STH.TenantID != tenantID {
		return domain.ErrSTHInvalid
	}
	if bundle.Inclusion.TenantID != "" && bundle.Inclusion.TenantID != tenantID {
		return domain.ErrLogProofInvalid
	}
	if bundle.Inclusion.STHTreeSize != bundle.STH.TreeSize {
		return domain.ErrLogProofInvalid
	}
	if !bytes.Equal(bundle.Inclusion.STHRootHash, bundle.STH.RootHash) {
		return domain.ErrLogProofInvalid
	}

	ok, err := uc.Merkle.VerifyInclusionProof(
		leafHash,
		bundle.Inclusion.LeafIndex,
		bundle.Inclusion.STHTreeSize,
		bundle.Inclusion.Path,
		bundle.Inclusion.STHRootHash,
	)
	if err != nil || !ok {
		return domain.ErrLogProofInvalid
	}
	return nil
}

func stringsEqualFoldHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ra := a[i]
		rb := b[i]
		if ra == rb {
			continue
		}
		if ra >= 'A' && ra <= 'F' {
			ra = ra - 'A' + 'a'
		}
		if rb >= 'A' && rb <= 'F' {
			rb = rb - 'A' + 'a'
		}
		if ra != rb {
			return false
		}
	}
	return true
}

func (uc *VerifySignedManifest) attachPolicy(ctx context.Context, receipt *VerifyReceipt, env domain.SignedManifestEnvelope, verification domain.PolicyVerification, requireProof bool) (*domain.PolicyEvaluation, error) {
	if uc.Policy == nil {
		return nil, nil
	}
	input := domain.PolicyInput{
		Envelope:     env,
		Verification: verification,
		Options: &domain.PolicyOptions{
			RequireProof: requireProof,
		},
		Derivation:      receipt.Derivation,
		RevocationEpoch: receipt.RevocationEpoch,
	}
	eval, err := uc.Policy.Evaluate(ctx, input)
	if err != nil {
		return nil, err
	}
	receipt.Policy = policyReceiptFromEvaluation(eval)
	return &eval, nil
}

func (uc *VerifySignedManifest) attachDerivation(ctx context.Context, receipt *VerifyReceipt, env domain.SignedManifestEnvelope) (*domain.DerivationSummary, error) {
	if uc.Derivation == nil {
		return nil, nil
	}
	summary, err := uc.Derivation.Verify(ctx, env.Manifest.TenantID, env.Manifest.ManifestID)
	if err != nil {
		return nil, err
	}
	receipt.Derivation = derivationReceiptFromSummary(summary)
	return &summary, nil
}

func policyReceiptFromEvaluation(eval domain.PolicyEvaluation) domain.PolicyReceipt {
	receipt := domain.PolicyReceipt{
		"bundle_hash": eval.BundleHash,
		"result":      eval.Result,
	}
	if eval.BundleID != "" {
		receipt["bundle_id"] = eval.BundleID
	}
	return receipt
}

func (uc *VerifySignedManifest) attachDecision(receipt *VerifyReceipt, eval *domain.PolicyEvaluation, derivation *domain.DerivationSummary, verification domain.PolicyVerification) error {
	if uc.Decision == nil || eval == nil {
		return nil
	}
	result, err := uc.Decision.Evaluate(DecisionInput{
		Verification:    verification,
		Derivation:      derivation,
		Policy:          eval.Result,
		RevocationEpoch: receipt.RevocationEpoch,
	})
	if err != nil {
		return err
	}
	receipt.Decision = decisionReceiptFromResult(result)
	return nil
}

func (uc *VerifySignedManifest) storeCache(ctx context.Context, key string, receipt *VerifyReceipt) {
	if uc.Cache == nil || uc.RevocationEpochs == nil || key == "" || receipt == nil || receipt.STH == nil {
		return
	}
	ttl := uc.CacheTTL
	if err := uc.Cache.Put(ctx, key, receiptToCache(receipt), ttl); err != nil {
		return
	}
}

func receiptFromCache(cached *domain.VerificationResult) *VerifyReceipt {
	if cached == nil {
		return nil
	}
	return &VerifyReceipt{
		SignatureValid:      cached.SignatureValid,
		KeyStatus:           cached.KeyStatus,
		RevocationCheckedAt: cached.RevocationCheckedAt,
		LogIncluded:         cached.LogIncluded,
		SubjectHash:         cached.SubjectHash,
		ManifestID:          cached.ManifestID,
		TenantID:            cached.TenantID,
		RevocationEpoch:     cached.RevocationEpoch,
		STH:                 cached.STH,
		InclusionProof:      cached.InclusionProof,
		Consistency:         cached.Consistency,
		Derivation:          cached.Derivation,
		Policy:              cached.Policy,
		Decision:            cached.Decision,
		Replay:              cached.Replay,
	}
}

func receiptToCache(receipt *VerifyReceipt) domain.VerificationResult {
	return domain.VerificationResult{
		SignatureValid:      receipt.SignatureValid,
		KeyStatus:           receipt.KeyStatus,
		RevocationCheckedAt: receipt.RevocationCheckedAt,
		LogIncluded:         receipt.LogIncluded,
		SubjectHash:         receipt.SubjectHash,
		ManifestID:          receipt.ManifestID,
		TenantID:            receipt.TenantID,
		RevocationEpoch:     receipt.RevocationEpoch,
		STH:                 receipt.STH,
		InclusionProof:      receipt.InclusionProof,
		Consistency:         receipt.Consistency,
		Derivation:          receipt.Derivation,
		Policy:              receipt.Policy,
		Decision:            receipt.Decision,
		Replay:              receipt.Replay,
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

func derivationReceiptFromSummary(summary domain.DerivationSummary) domain.DerivationReceipt {
	receipt := domain.DerivationReceipt{
		"complete": summary.Complete,
		"depth":    summary.Depth,
		"severity": summary.Severity,
	}
	if len(summary.Failures) > 0 {
		receipt["failures"] = summary.Failures
	}
	return receipt
}

func decisionReceiptFromResult(result DecisionResult) domain.DecisionReceipt {
	receipt := domain.DecisionReceipt{
		"engine_version": result.EngineVersion,
		"action":         result.Action,
		"score":          result.Score,
		"reasons":        result.Reasons,
	}
	return receipt
}

func buildPolicyVerification(receipt *VerifyReceipt, artifactHashValid *bool) domain.PolicyVerification {
	return domain.PolicyVerification{
		SignatureValid:    receipt.SignatureValid,
		KeyStatus:         receipt.KeyStatus,
		LogIncluded:       receipt.LogIncluded,
		ArtifactHashValid: artifactHashValid,
	}
}
