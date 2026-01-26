package replay

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
)

type ReplayBundle struct {
	Envelope           domain.SignedManifestEnvelope `json:"envelope"`
	Proof              ReplayProof                   `json:"proof"`
	Derivation         domain.DerivationReceipt      `json:"derivation,omitempty"`
	Policy             *PolicyReplay                 `json:"policy,omitempty"`
	Decision           domain.DecisionReceipt        `json:"decision,omitempty"`
	Engines            EngineVersions                `json:"engines"`
	RevocationEpoch    int64                         `json:"revocation_epoch"`
	ReplayInputsDigest string                        `json:"replay_inputs_digest,omitempty"`
}

type ReplayProof struct {
	STH            ReplaySTH            `json:"sth"`
	InclusionProof ReplayInclusionProof `json:"inclusion_proof"`
}

type ReplaySTH struct {
	TenantID  string `json:"tenant_id,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type ReplayInclusionProof struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
}

type PolicyReplay struct {
	BundleID   string               `json:"bundle_id,omitempty"`
	BundleHash string               `json:"bundle_hash"`
	Result     domain.PolicyReceipt `json:"result,omitempty"`
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
	InclusionProof ReplayInclusionProof `json:"inclusion_proof"`
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

type EngineVersions struct {
	Verification string `json:"verification"`
	Derivation   string `json:"derivation,omitempty"`
	Policy       string `json:"policy"`
	Decision     string `json:"decision"`
}

const (
	DefaultVerificationEngineVersion = "verification.v0.0.1"
	DefaultPolicyEngineVersion       = "policy.v0.0.1"
	DefaultDecisionEngineVersion     = "decision.v0.0.1"
)

type BundleInput struct {
	Envelope           domain.SignedManifestEnvelope
	STH                domain.STH
	STHSignature       string
	Inclusion          domain.InclusionProof
	Derivation         domain.DerivationReceipt
	PolicyBundle       any
	PolicyBundleID     string
	PolicyBundleHash   string
	PolicyResult       domain.PolicyReceipt
	PolicyEvaluation   *domain.PolicyEvaluation
	DecisionResult     domain.DecisionReceipt
	Engines            EngineVersions
	RevocationEpoch    int64
	ReplayInputsDigest string
}

func BuildReplayBundle(input BundleInput) (ReplayBundle, error) {
	engines := applyDefaultEngines(input.Engines)
	if engines.Verification == "" || engines.Policy == "" || engines.Decision == "" {
		return ReplayBundle{}, errors.New("engine versions are required")
	}

	signature := input.STHSignature
	if signature == "" && len(input.STH.Signature) > 0 {
		signature = base64.StdEncoding.EncodeToString(input.STH.Signature)
	}
	if signature == "" {
		return ReplayBundle{}, errors.New("sth signature is required")
	}

	proof := ReplayProof{
		STH:            buildReplaySTH(input.STH, signature),
		InclusionProof: buildReplayInclusion(input.Inclusion),
	}

	policy, err := buildPolicyReplay(input)
	if err != nil {
		return ReplayBundle{}, err
	}

	bundle := ReplayBundle{
		Envelope:           input.Envelope,
		Proof:              proof,
		Derivation:         input.Derivation,
		Policy:             policy,
		Decision:           input.DecisionResult,
		Engines:            engines,
		RevocationEpoch:    input.RevocationEpoch,
		ReplayInputsDigest: input.ReplayInputsDigest,
	}
	if bundle.ReplayInputsDigest == "" {
		digest, err := ComputeReplayInputsDigest(bundle)
		if err != nil {
			return ReplayBundle{}, err
		}
		bundle.ReplayInputsDigest = digest
	}
	return bundle, nil
}

func applyDefaultEngines(engines EngineVersions) EngineVersions {
	if engines.Verification == "" {
		engines.Verification = DefaultVerificationEngineVersion
	}
	if engines.Policy == "" {
		engines.Policy = DefaultPolicyEngineVersion
	}
	if engines.Decision == "" {
		engines.Decision = DefaultDecisionEngineVersion
	}
	return engines
}

func MarshalBundle(bundle ReplayBundle) ([]byte, error) {
	return cryptoinfra.CanonicalizeAny(bundle)
}

func ComputePolicyBundleHash(bundle any) (string, error) {
	canonical, err := cryptoinfra.CanonicalizeAny(bundle)
	if err != nil {
		return "", err
	}
	sum := sha256Hex(canonical)
	return sum, nil
}

func ComputeReplayInputsDigest(bundle ReplayBundle) (string, error) {
	inputs := buildReplayInputs(bundle)
	canonical, err := cryptoinfra.CanonicalizeAny(inputs)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func buildReplaySTH(sth domain.STH, signature string) ReplaySTH {
	issued := sth.IssuedAt
	if issued.IsZero() {
		issued = time.Time{}
	}
	return ReplaySTH{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  hex.EncodeToString(sth.RootHash),
		IssuedAt:  issued.UTC().Format(time.RFC3339),
		Signature: signature,
	}
}

func buildReplayInclusion(inclusion domain.InclusionProof) ReplayInclusionProof {
	path := make([]string, 0, len(inclusion.Path))
	for _, node := range inclusion.Path {
		path = append(path, hex.EncodeToString(node))
	}
	return ReplayInclusionProof{
		TenantID:    inclusion.TenantID,
		LeafIndex:   inclusion.LeafIndex,
		Path:        path,
		STHTreeSize: inclusion.STHTreeSize,
		STHRootHash: hex.EncodeToString(inclusion.STHRootHash),
	}
}

func buildPolicyReplay(input BundleInput) (*PolicyReplay, error) {
	policyBundleID := input.PolicyBundleID
	policyBundleHash := input.PolicyBundleHash
	policyResult := input.PolicyResult

	if input.PolicyEvaluation != nil {
		policyBundleID = input.PolicyEvaluation.BundleID
		policyBundleHash = input.PolicyEvaluation.BundleHash
		if policyResult == nil {
			policyResult = domain.PolicyReceipt{
				"allow": input.PolicyEvaluation.Result.Allow,
				"deny":  input.PolicyEvaluation.Result.Deny,
			}
		}
	}

	hasPolicy := policyResult != nil || input.PolicyBundle != nil || policyBundleHash != "" || policyBundleID != ""
	if !hasPolicy {
		return nil, nil
	}

	bundleHash := policyBundleHash
	if bundleHash == "" && input.PolicyBundle != nil {
		hash, err := ComputePolicyBundleHash(input.PolicyBundle)
		if err != nil {
			return nil, err
		}
		bundleHash = hash
	}
	if bundleHash == "" {
		return nil, errors.New("policy bundle hash is required when policy data is present")
	}

	return &PolicyReplay{
		BundleID:   policyBundleID,
		BundleHash: bundleHash,
		Result:     policyResult,
	}, nil
}

func buildReplayInputs(bundle ReplayBundle) replayInputs {
	inputs := replayInputs{
		Envelope:   bundle.Envelope,
		Derivation: bundle.Derivation,
		Decision:   bundle.Decision,
		Engines:    bundle.Engines,
		RevocationEpoch: bundle.RevocationEpoch,
	}
	if bundle.Policy != nil {
		inputs.Policy = &replayInputsPolicy{
			BundleHash: bundle.Policy.BundleHash,
			Result:     bundle.Policy.Result,
		}
	}
	inputs.Proof = replayInputsProof{
		STH: replayInputsSTH{
			TenantID: bundle.Proof.STH.TenantID,
			TreeSize: bundle.Proof.STH.TreeSize,
			RootHash: bundle.Proof.STH.RootHash,
		},
		InclusionProof: bundle.Proof.InclusionProof,
	}
	return inputs
}
