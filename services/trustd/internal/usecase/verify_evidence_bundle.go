package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"proteus/internal/domain"
)

const (
	EvidenceFailInvalidBundle           = "INVALID_BUNDLE"
	EvidenceFailSignatureInvalid        = "SIGNATURE_INVALID"
	EvidenceFailSTHSignatureInvalid     = "STH_SIGNATURE_INVALID"
	EvidenceFailLogProofInvalid         = "LOG_PROOF_INVALID"
	EvidenceFailReceiptDigestMismatch   = "RECEIPT_DIGEST_MISMATCH"
	EvidenceFailReplayDigestMismatch    = "REPLAY_INPUTS_DIGEST_MISMATCH"
	EvidenceFailPolicyEngineMissing     = "POLICY_ENGINE_MISSING"
	EvidenceFailDecisionEngineMissing   = "DECISION_ENGINE_MISSING"
	EvidenceFailPolicyBundleHashMismatch = "POLICY_BUNDLE_HASH_MISMATCH"
	EvidenceFailPolicyMismatch          = "POLICY_MISMATCH"
	EvidenceFailDecisionMismatch        = "DECISION_MISMATCH"
)

type EvidenceBundle struct {
	BundleID           string         `json:"bundle_id"`
	Version            string         `json:"version"`
	Envelopes          []EnvelopeEntry `json:"envelopes"`
	Manifests          []ManifestEntry `json:"manifests"`
	Keys               EvidenceKeys   `json:"keys"`
	Revocations        []RevocationStatement `json:"revocations"`
	Proofs             EvidenceProofs `json:"proofs"`
	Derivation         *domain.DerivationSummary `json:"derivation,omitempty"`
	Receipt            EvidenceReceipt `json:"receipt"`
	ReceiptDigest      string         `json:"receipt_digest"`
	ReplayInputsDigest string         `json:"replay_inputs_digest"`
	Engines            EngineVersions `json:"engines"`
	RevocationEpoch    int64          `json:"revocation_epoch"`
}

type EnvelopeEntry struct {
	Manifest  ManifestEntry  `json:"manifest"`
	Signature domain.Signature `json:"signature"`
	CertChain []string       `json:"cert_chain,omitempty"`
}

type ManifestEntry struct {
	Schema     string                `json:"schema"`
	ManifestID string                `json:"manifest_id"`
	TenantID   string                `json:"tenant_id"`
	Subject    domain.Subject        `json:"subject"`
	Actor      domain.Actor          `json:"actor"`
	Tool       domain.Tool           `json:"tool"`
	Time       domain.ManifestTime   `json:"time"`
	Inputs     *[]domain.InputArtifact `json:"inputs,omitempty"`
	Claims     *map[string]any       `json:"claims,omitempty"`
}

type EvidenceKeys struct {
	Signing []KeyDescriptor `json:"signing"`
	Log     []KeyDescriptor `json:"log"`
}

type KeyDescriptor struct {
	KID             string `json:"kid"`
	Alg             string `json:"alg"`
	PublicKeyBase64 string `json:"public_key_base64"`
	Status          string `json:"status,omitempty"`
}

type RevocationStatement struct {
	KID       string `json:"kid"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
}

type EvidenceProofs struct {
	STHs            []STHEntry       `json:"sths"`
	InclusionProofs []InclusionEntry `json:"inclusion_proofs"`
}

type STHEntry struct {
	TenantID  string `json:"tenant_id,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type InclusionEntry struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
}

type EvidenceReceipt struct {
	SignatureValid      bool                 `json:"signature_valid"`
	KeyStatus           string               `json:"key_status"`
	RevocationCheckedAt string               `json:"revocation_checked_at"`
	LogIncluded         bool                 `json:"log_included"`
	SubjectHash         domain.Hash          `json:"subject_hash"`
	ManifestID          string               `json:"manifest_id"`
	TenantID            string               `json:"tenant_id"`
	STH                *STHEntry            `json:"sth,omitempty"`
	InclusionProof      *InclusionEntry     `json:"inclusion_proof,omitempty"`
	ConsistencyProof    *ConsistencyEntry   `json:"consistency_proof,omitempty"`
	Derivation          domain.DerivationReceipt `json:"derivation,omitempty"`
	Policy              domain.PolicyReceipt     `json:"policy,omitempty"`
	Decision            domain.DecisionReceipt   `json:"decision,omitempty"`
	Replay              domain.ReplayReceipt     `json:"replay,omitempty"`
}

type ConsistencyEntry struct {
	TenantID string   `json:"tenant_id,omitempty"`
	FromSize int64    `json:"from_size"`
	ToSize   int64    `json:"to_size"`
	Path     []string `json:"path"`
}

type EngineVersions struct {
	Verification string `json:"verification"`
	Derivation   string `json:"derivation,omitempty"`
	Policy       string `json:"policy"`
	Decision     string `json:"decision"`
}

type VerifyEvidenceBundle struct {
	Crypto   CryptoService
	Merkle   MerkleService
	Policy   PolicyEngine
	Decision DecisionEngine
}

type EvidenceVerificationResult struct {
	Passed   bool
	Failures []string
}

func (e EnvelopeEntry) ToDomain() domain.SignedManifestEnvelope {
	return domain.SignedManifestEnvelope{
		Manifest:  e.Manifest.ToDomain(),
		Signature: e.Signature,
		CertChain: e.CertChain,
	}
}

func (m ManifestEntry) ToDomain() domain.Manifest {
	manifest := domain.Manifest{
		Schema:     m.Schema,
		ManifestID: m.ManifestID,
		TenantID:   m.TenantID,
		Subject:    m.Subject,
		Actor:      m.Actor,
		Tool:       m.Tool,
		Time:       m.Time,
	}
	if m.Inputs != nil {
		manifest.Inputs = make([]domain.InputArtifact, len(*m.Inputs))
		copy(manifest.Inputs, *m.Inputs)
	}
	if m.Claims != nil {
		claims := make(map[string]any, len(*m.Claims))
		for key, value := range *m.Claims {
			claims[key] = value
		}
		manifest.Claims = claims
	}
	return manifest
}

func (uc *VerifyEvidenceBundle) Execute(ctx context.Context, bundle EvidenceBundle) (EvidenceVerificationResult, error) {
	if uc == nil || uc.Crypto == nil || uc.Merkle == nil {
		return EvidenceVerificationResult{}, errors.New("crypto and merkle services are required")
	}
	failures := make(map[string]struct{})
	addFailure := func(code string) {
		if code == "" {
			return
		}
		failures[code] = struct{}{}
	}

	if len(bundle.Envelopes) == 0 || len(bundle.Proofs.InclusionProofs) == 0 || len(bundle.Proofs.STHs) == 0 {
		addFailure(EvidenceFailInvalidBundle)
		return finalizeEvidenceResult(failures), nil
	}

	signingKeys := map[string]KeyDescriptor{}
	for _, key := range bundle.Keys.Signing {
		if key.KID != "" {
			signingKeys[key.KID] = key
		}
	}

	logKeys := make([]KeyDescriptor, 0, len(bundle.Keys.Log))
	for _, key := range bundle.Keys.Log {
		if key.KID != "" {
			logKeys = append(logKeys, key)
		}
	}

	signatureValid := true
	logIncluded := true
	keyStatus := bundle.Receipt.KeyStatus
	envelopes := bundle.Envelopes
	for idx, envEntry := range envelopes {
		if err := ctx.Err(); err != nil {
			return EvidenceVerificationResult{}, err
		}
		env := envEntry.ToDomain()
		signingKey, ok := signingKeys[env.Signature.KID]
		if !ok {
			signatureValid = false
			addFailure(EvidenceFailSignatureInvalid)
			continue
		}
		pubKey, err := decodeBase64String(signingKey.PublicKeyBase64)
		if err != nil {
			signatureValid = false
			addFailure(EvidenceFailSignatureInvalid)
			continue
		}
		canonical, err := uc.Crypto.CanonicalizeManifest(env.Manifest)
		if err != nil {
			return EvidenceVerificationResult{}, err
		}
		if err := uc.Crypto.VerifySignature(canonical, env.Signature, pubKey); err != nil {
			signatureValid = false
			addFailure(EvidenceFailSignatureInvalid)
			continue
		}
		if signingKey.Status != "" {
			keyStatus = signingKey.Status
		}

		if idx >= len(bundle.Proofs.InclusionProofs) {
			logIncluded = false
			addFailure(EvidenceFailLogProofInvalid)
			continue
		}
		inclusion := bundle.Proofs.InclusionProofs[idx]
		sth, ok := matchSTH(inclusion, bundle.Proofs.STHs)
		if !ok {
			logIncluded = false
			addFailure(EvidenceFailLogProofInvalid)
			continue
		}
		if !verifySTHSignature(uc, sth, logKeys) {
			logIncluded = false
			addFailure(EvidenceFailSTHSignatureInvalid)
		}

		leafHash, err := uc.Crypto.ComputeLeafHash(env)
		if err != nil {
			return EvidenceVerificationResult{}, err
		}
		okProof, err := uc.Merkle.VerifyInclusionProof(
			leafHash,
			inclusion.LeafIndex,
			inclusion.STHTreeSize,
			decodeHexPathStrings(inclusion.Path),
			decodeHexString(inclusion.STHRootHash),
		)
		if err != nil || !okProof {
			logIncluded = false
			addFailure(EvidenceFailLogProofInvalid)
		}
	}

	if bundle.ReceiptDigest != "" {
		receiptDigest, err := computeReceiptDigest(uc, bundle.Receipt)
		if err != nil {
			return EvidenceVerificationResult{}, err
		}
		if receiptDigest != bundle.ReceiptDigest {
			addFailure(EvidenceFailReceiptDigestMismatch)
		}
	}

	replayDigest, err := computeReplayInputsDigest(uc, bundle)
	if err != nil {
		return EvidenceVerificationResult{}, err
	}
	if bundle.ReplayInputsDigest != "" && replayDigest != bundle.ReplayInputsDigest {
		addFailure(EvidenceFailReplayDigestMismatch)
	}

	if uc.Policy == nil {
		addFailure(EvidenceFailPolicyEngineMissing)
	} else {
		env := bundle.Envelopes[0].ToDomain()
		verification := domain.PolicyVerification{
			SignatureValid: signatureValid,
			KeyStatus:      keyStatus,
			LogIncluded:    logIncluded,
		}
		policyInput := domain.PolicyInput{
			Envelope:         env,
			Verification:     verification,
			Options: &domain.PolicyOptions{
				RequireProof: false,
			},
			Derivation:      bundle.Receipt.Derivation,
			RevocationEpoch: bundle.RevocationEpoch,
		}
		eval, err := uc.Policy.Evaluate(ctx, policyInput)
		if err != nil {
			return EvidenceVerificationResult{}, err
		}
		receiptEval, err := evidencePolicyEvaluationFromReceipt(bundle.Receipt.Policy)
		if err != nil {
			addFailure(EvidenceFailPolicyMismatch)
		} else {
			eval = normalizePolicyEval(eval)
			receiptEval = normalizePolicyEval(receiptEval)
			if eval.BundleHash != "" && receiptEval.BundleHash != "" && eval.BundleHash != receiptEval.BundleHash {
				addFailure(EvidenceFailPolicyBundleHashMismatch)
			}
			if !policyResultsEqual(eval.Result, receiptEval.Result) {
				addFailure(EvidenceFailPolicyMismatch)
			}
		}

		if uc.Decision == nil {
			addFailure(EvidenceFailDecisionEngineMissing)
		} else {
			decisionResult, err := uc.Decision.Evaluate(DecisionInput{
				Verification:    verification,
				Derivation:      bundle.Derivation,
				Policy:          eval.Result,
				RevocationEpoch: bundle.RevocationEpoch,
			})
			if err != nil {
				return EvidenceVerificationResult{}, err
			}
			expected, err := evidenceDecisionFromReceipt(bundle.Receipt.Decision)
			if err != nil {
				addFailure(EvidenceFailDecisionMismatch)
			} else if !decisionEquals(decisionResult, expected) {
				addFailure(EvidenceFailDecisionMismatch)
			}
		}
	}

	return finalizeEvidenceResult(failures), nil
}

func finalizeEvidenceResult(failures map[string]struct{}) EvidenceVerificationResult {
	out := EvidenceVerificationResult{
		Failures: make([]string, 0, len(failures)),
	}
	for code := range failures {
		out.Failures = append(out.Failures, code)
	}
	sort.Strings(out.Failures)
	out.Passed = len(out.Failures) == 0
	return out
}

func matchSTH(inclusion InclusionEntry, sths []STHEntry) (STHEntry, bool) {
	for _, sth := range sths {
		if sth.TreeSize == inclusion.STHTreeSize && strings.EqualFold(sth.RootHash, inclusion.STHRootHash) {
			if inclusion.TenantID == "" || sth.TenantID == "" || inclusion.TenantID == sth.TenantID {
				return sth, true
			}
		}
	}
	return STHEntry{}, false
}

func verifySTHSignature(uc *VerifyEvidenceBundle, sth STHEntry, logKeys []KeyDescriptor) bool {
	if sth.Signature == "" {
		return false
	}
	root := decodeHexString(sth.RootHash)
	issuedAt := sth.IssuedAt
	parsed, err := timeParseRFC3339(issuedAt)
	if err != nil {
		return false
	}
	treeHead := domain.STH{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  root,
		IssuedAt:  parsed,
	}
	for _, key := range logKeys {
		pubKey, err := decodeBase64String(key.PublicKeyBase64)
		if err != nil {
			continue
		}
		if err := uc.Crypto.VerifySTHSignature(treeHead, sth.Signature, pubKey); err == nil {
			return true
		}
	}
	return false
}

func computeReceiptDigest(uc *VerifyEvidenceBundle, receipt EvidenceReceipt) (string, error) {
	canonical, err := uc.Crypto.CanonicalizeAny(receipt)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

type replayInputs struct {
	Envelope   domain.SignedManifestEnvelope `json:"envelope"`
	Proof      replayInputsProof             `json:"proof"`
	Derivation domain.DerivationReceipt      `json:"derivation,omitempty"`
	Policy     *replayInputsPolicy           `json:"policy,omitempty"`
	Decision   domain.DecisionReceipt        `json:"decision,omitempty"`
	Engines    EngineVersions                `json:"engines"`
	RevocationEpoch int64                    `json:"revocation_epoch"`
}

type replayInputsProof struct {
	STH            replayInputsSTH      `json:"sth"`
	InclusionProof InclusionEntry       `json:"inclusion_proof"`
}

type replayInputsSTH struct {
	TenantID string `json:"tenant_id,omitempty"`
	TreeSize int64  `json:"tree_size"`
	RootHash string `json:"root_hash"`
}

type replayInputsPolicy struct {
	BundleHash string               `json:"bundle_hash"`
	Result     domain.PolicyReceipt `json:"result,omitempty"`
}

func computeReplayInputsDigest(uc *VerifyEvidenceBundle, bundle EvidenceBundle) (string, error) {
	if len(bundle.Envelopes) == 0 || len(bundle.Proofs.InclusionProofs) == 0 || len(bundle.Proofs.STHs) == 0 {
		return "", errors.New("bundle missing envelope or proofs")
	}
	sth, ok := matchSTH(bundle.Proofs.InclusionProofs[0], bundle.Proofs.STHs)
	if !ok {
		sth = bundle.Proofs.STHs[0]
	}
	inputs := replayInputs{
		Envelope:   bundle.Envelopes[0].ToDomain(),
		Derivation: bundle.Receipt.Derivation,
		Decision:   bundle.Receipt.Decision,
		Engines:    bundle.Engines,
		RevocationEpoch: bundle.RevocationEpoch,
		Proof: replayInputsProof{
			STH: replayInputsSTH{
				TenantID: sth.TenantID,
				TreeSize: sth.TreeSize,
				RootHash: sth.RootHash,
			},
			InclusionProof: bundle.Proofs.InclusionProofs[0],
		},
	}
	if bundle.Receipt.Policy != nil {
		eval, err := evidencePolicyEvaluationFromReceipt(bundle.Receipt.Policy)
		if err != nil {
			return "", err
		}
		inputs.Policy = &replayInputsPolicy{
			BundleHash: eval.BundleHash,
			Result:     policyResultReceipt(eval.Result),
		}
	}
	canonical, err := uc.Crypto.CanonicalizeAny(inputs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

type decisionPayload struct {
	EngineVersion string   `json:"engine_version"`
	Action        string   `json:"action"`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons,omitempty"`
}

func evidenceDecisionFromReceipt(receipt domain.DecisionReceipt) (decisionPayload, error) {
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

func decisionEquals(result DecisionResult, receipt decisionPayload) bool {
	if result.EngineVersion != receipt.EngineVersion {
		return false
	}
	if result.Action != receipt.Action || result.Score != receipt.Score {
		return false
	}
	if len(result.Reasons) != len(receipt.Reasons) {
		return false
	}
	for i := range result.Reasons {
		if result.Reasons[i] != receipt.Reasons[i] {
			return false
		}
	}
	return true
}

func evidencePolicyEvaluationFromReceipt(receipt domain.PolicyReceipt) (domain.PolicyEvaluation, error) {
	if receipt == nil {
		return domain.PolicyEvaluation{}, errors.New("policy receipt is required")
	}
	hash, ok := receipt["bundle_hash"].(string)
	if !ok || hash == "" {
		return domain.PolicyEvaluation{}, errors.New("policy bundle_hash is required")
	}
	resultValue, ok := receipt["result"]
	if !ok {
		return domain.PolicyEvaluation{}, errors.New("policy result is required")
	}
	result, ok := resultValue.(domain.PolicyResult)
	if !ok {
		payload, err := json.Marshal(resultValue)
		if err != nil {
			return domain.PolicyEvaluation{}, errors.New("policy result type is invalid")
		}
		if err := json.Unmarshal(payload, &result); err != nil {
			return domain.PolicyEvaluation{}, errors.New("policy result type is invalid")
		}
	}
	eval := domain.PolicyEvaluation{
		BundleHash: hash,
		Result:     result,
	}
	if bundleID, ok := receipt["bundle_id"].(string); ok {
		eval.BundleID = bundleID
	}
	return eval, nil
}

func normalizePolicyEval(eval domain.PolicyEvaluation) domain.PolicyEvaluation {
	if len(eval.Result.Deny) == 0 {
		eval.Result.Deny = nil
	}
	return eval
}

func policyResultsEqual(a, b domain.PolicyResult) bool {
	if a.Allow != b.Allow {
		return false
	}
	if len(a.Deny) != len(b.Deny) {
		return false
	}
	for i := range a.Deny {
		if a.Deny[i].Code != b.Deny[i].Code || a.Deny[i].Message != b.Deny[i].Message {
			return false
		}
	}
	return true
}

func policyResultReceipt(result domain.PolicyResult) domain.PolicyReceipt {
	deny := result.Deny
	if deny == nil {
		deny = []domain.PolicyDeny{}
	}
	return domain.PolicyReceipt{
		"allow": result.Allow,
		"deny":  deny,
	}
}

func decodeHexString(value string) []byte {
	out, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return out
}

func decodeHexPathStrings(values []string) [][]byte {
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		out = append(out, decodeHexString(value))
	}
	return out
}

func decodeBase64String(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(value))
}

func timeParseRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("issued_at is required")
	}
	return time.Parse(time.RFC3339, value)
}
