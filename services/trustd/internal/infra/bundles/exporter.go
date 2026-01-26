package bundles

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
	"proteus/internal/infra/replay"
)

const EvidenceBundleVersion = "v0"

type BundleInput struct {
	BundleID        string
	Envelopes       []domain.SignedManifestEnvelope
	Proofs          []ProofInput
	Receipt         Receipt
	Derivation      *domain.DerivationSummary
	PolicyEvaluation *domain.PolicyEvaluation
	Decision        domain.DecisionReceipt
	Engines         replay.EngineVersions
	SigningKeys     []domain.SigningKey
	LogKeys         []domain.SigningKey
	Revocations     []domain.Revocation
	RevocationEpoch int64
}

type ProofInput struct {
	STH          domain.STH
	STHSignature string
	Inclusion    domain.InclusionProof
}

type EvidenceBundle struct {
	BundleID           string            `json:"bundle_id"`
	Version            string            `json:"version"`
	Envelopes          []EnvelopeEntry   `json:"envelopes"`
	Manifests          []ManifestEntry   `json:"manifests"`
	Keys               EvidenceKeys      `json:"keys"`
	Revocations        []RevocationStatement `json:"revocations"`
	Proofs             EvidenceProofs    `json:"proofs"`
	Derivation         *domain.DerivationSummary `json:"derivation,omitempty"`
	Receipt            Receipt           `json:"receipt"`
	ReceiptDigest      string            `json:"receipt_digest"`
	ReplayInputsDigest string            `json:"replay_inputs_digest"`
	Engines            replay.EngineVersions `json:"engines"`
	RevocationEpoch    int64             `json:"revocation_epoch"`
}

type EvidenceKeys struct {
	Signing []KeyDescriptor `json:"signing"`
	Log     []KeyDescriptor `json:"log"`
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

type KeyDescriptor struct {
	KID              string `json:"kid"`
	Alg              string `json:"alg"`
	PublicKeyBase64  string `json:"public_key_base64"`
	Status           string `json:"status,omitempty"`
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

type Receipt struct {
	SignatureValid      bool                 `json:"signature_valid"`
	KeyStatus           string               `json:"key_status"`
	RevocationCheckedAt string               `json:"revocation_checked_at"`
	LogIncluded         bool                 `json:"log_included"`
	SubjectHash         domain.Hash          `json:"subject_hash"`
	ManifestID          string               `json:"manifest_id"`
	TenantID            string               `json:"tenant_id"`
	STH                *STHEntry             `json:"sth,omitempty"`
	InclusionProof      *InclusionEntry      `json:"inclusion_proof,omitempty"`
	ConsistencyProof    *ConsistencyEntry    `json:"consistency_proof,omitempty"`
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

func BuildEvidenceBundle(input BundleInput) (EvidenceBundle, error) {
	if input.BundleID == "" {
		return EvidenceBundle{}, errors.New("bundle_id is required")
	}
	if len(input.Envelopes) == 0 {
		return EvidenceBundle{}, errors.New("at least one envelope is required")
	}
	if len(input.Proofs) == 0 {
		return EvidenceBundle{}, errors.New("at least one proof is required")
	}

	envelopes := sortedEnvelopes(input.Envelopes)
	envelopeEntries := buildEnvelopeEntries(envelopes)
	manifests := dedupeManifests(envelopes)
	sths := make([]STHEntry, 0, len(input.Proofs))
	inclusions := make([]InclusionEntry, 0, len(input.Proofs))

	for _, proof := range input.Proofs {
		sthSig := proof.STHSignature
		if sthSig == "" && len(proof.STH.Signature) > 0 {
			sthSig = base64.StdEncoding.EncodeToString(proof.STH.Signature)
		}
		if sthSig == "" {
			return EvidenceBundle{}, errors.New("sth signature is required")
		}
		sths = append(sths, buildSTHEntry(proof.STH, sthSig))
		inclusions = append(inclusions, buildInclusionEntry(proof.Inclusion))
	}

	sortSTHs(sths)
	sortInclusions(inclusions)

	receipt := input.Receipt
	hydrateReceipt(&receipt, input.PolicyEvaluation, input.Decision)

	receiptDigest, err := computeReceiptDigest(receipt)
	if err != nil {
		return EvidenceBundle{}, err
	}

	replayDigest, err := computeReplayInputsDigest(input, receipt)
	if err != nil {
		return EvidenceBundle{}, err
	}

	keys := EvidenceKeys{
		Signing: buildKeyDescriptors(input.SigningKeys),
		Log:     buildKeyDescriptors(input.LogKeys),
	}
	revocations := buildRevocationStatements(input.Revocations)

	bundle := EvidenceBundle{
		BundleID:           input.BundleID,
		Version:            EvidenceBundleVersion,
		Envelopes:          envelopeEntries,
		Manifests:          manifests,
		Keys:               keys,
		Revocations:        revocations,
		Proofs:             EvidenceProofs{STHs: sths, InclusionProofs: inclusions},
		Derivation:         input.Derivation,
		Receipt:            receipt,
		ReceiptDigest:      receiptDigest,
		ReplayInputsDigest: replayDigest,
		Engines:            applyDefaultEngines(input.Engines),
		RevocationEpoch:    input.RevocationEpoch,
	}
	return bundle, nil
}

func MarshalEvidenceBundle(bundle EvidenceBundle) ([]byte, error) {
	return cryptoinfra.CanonicalizeAny(bundle)
}

func ExportJSON(input BundleInput) ([]byte, error) {
	bundle, err := BuildEvidenceBundle(input)
	if err != nil {
		return nil, err
	}
	return MarshalEvidenceBundle(bundle)
}

func buildSTHEntry(sth domain.STH, signature string) STHEntry {
	return STHEntry{
		TenantID:  sth.TenantID,
		TreeSize:  sth.TreeSize,
		RootHash:  hex.EncodeToString(sth.RootHash),
		IssuedAt:  sth.IssuedAt.UTC().Format(time.RFC3339),
		Signature: signature,
	}
}

func buildInclusionEntry(inclusion domain.InclusionProof) InclusionEntry {
	path := make([]string, 0, len(inclusion.Path))
	for _, node := range inclusion.Path {
		path = append(path, hex.EncodeToString(node))
	}
	return InclusionEntry{
		TenantID:    inclusion.TenantID,
		LeafIndex:   inclusion.LeafIndex,
		Path:        path,
		STHTreeSize: inclusion.STHTreeSize,
		STHRootHash: hex.EncodeToString(inclusion.STHRootHash),
	}
}

func buildConsistencyEntry(consistency domain.ConsistencyProof) ConsistencyEntry {
	path := make([]string, 0, len(consistency.Path))
	for _, node := range consistency.Path {
		path = append(path, hex.EncodeToString(node))
	}
	return ConsistencyEntry{
		TenantID: consistency.TenantID,
		FromSize: consistency.FromSize,
		ToSize:   consistency.ToSize,
		Path:     path,
	}
}

func sortedEnvelopes(envelopes []domain.SignedManifestEnvelope) []domain.SignedManifestEnvelope {
	out := make([]domain.SignedManifestEnvelope, len(envelopes))
	copy(out, envelopes)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Manifest.ManifestID < out[j].Manifest.ManifestID
	})
	return out
}

func buildEnvelopeEntries(envelopes []domain.SignedManifestEnvelope) []EnvelopeEntry {
	out := make([]EnvelopeEntry, 0, len(envelopes))
	for _, env := range envelopes {
		out = append(out, EnvelopeEntry{
			Manifest:  manifestEntryFromDomain(env.Manifest),
			Signature: env.Signature,
			CertChain: env.CertChain,
		})
	}
	return out
}

func manifestEntryFromDomain(manifest domain.Manifest) ManifestEntry {
	entry := ManifestEntry{
		Schema:     manifest.Schema,
		ManifestID: manifest.ManifestID,
		TenantID:   manifest.TenantID,
		Subject:    manifest.Subject,
		Actor:      manifest.Actor,
		Tool:       manifest.Tool,
		Time:       manifest.Time,
	}
	if manifest.Inputs != nil {
		inputs := make([]domain.InputArtifact, len(manifest.Inputs))
		copy(inputs, manifest.Inputs)
		entry.Inputs = &inputs
	}
	if manifest.Claims != nil {
		claims := make(map[string]any, len(manifest.Claims))
		for key, value := range manifest.Claims {
			claims[key] = value
		}
		entry.Claims = &claims
	}
	return entry
}

func dedupeManifests(envelopes []domain.SignedManifestEnvelope) []ManifestEntry {
	seen := make(map[string]ManifestEntry, len(envelopes))
	for _, env := range envelopes {
		manifest := env.Manifest
		if manifest.ManifestID == "" {
			continue
		}
		seen[manifest.ManifestID] = manifestEntryFromDomain(manifest)
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ManifestEntry, 0, len(ids))
	for _, id := range ids {
		out = append(out, seen[id])
	}
	return out
}

func sortSTHs(sths []STHEntry) {
	sort.Slice(sths, func(i, j int) bool {
		if sths[i].TreeSize == sths[j].TreeSize {
			return sths[i].RootHash < sths[j].RootHash
		}
		return sths[i].TreeSize < sths[j].TreeSize
	})
}

func sortInclusions(inclusions []InclusionEntry) {
	sort.Slice(inclusions, func(i, j int) bool {
		if inclusions[i].LeafIndex == inclusions[j].LeafIndex {
			return inclusions[i].STHTreeSize < inclusions[j].STHTreeSize
		}
		return inclusions[i].LeafIndex < inclusions[j].LeafIndex
	})
}

func buildKeyDescriptors(keys []domain.SigningKey) []KeyDescriptor {
	out := make([]KeyDescriptor, 0, len(keys))
	for _, key := range keys {
		desc := KeyDescriptor{
			KID:             key.KID,
			Alg:             key.Alg,
			PublicKeyBase64: base64.StdEncoding.EncodeToString(key.PublicKey),
			Status:          string(key.Status),
		}
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].KID < out[j].KID
	})
	return out
}

func buildRevocationStatements(revocations []domain.Revocation) []RevocationStatement {
	out := make([]RevocationStatement, 0, len(revocations))
	for _, rev := range revocations {
		out = append(out, RevocationStatement{
			KID:       rev.KID,
			RevokedAt: rev.RevokedAt.UTC().Format(time.RFC3339),
			Reason:    rev.Reason,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KID == out[j].KID {
			return out[i].RevokedAt < out[j].RevokedAt
		}
		return out[i].KID < out[j].KID
	})
	return out
}

func hydrateReceipt(receipt *Receipt, eval *domain.PolicyEvaluation, decision domain.DecisionReceipt) {
	if receipt == nil {
		return
	}
	if receipt.Policy == nil && eval != nil {
		receipt.Policy = policyReceiptFromEvaluation(*eval)
	}
	if receipt.Decision == nil && decision != nil {
		receipt.Decision = decision
	}
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

func computeReceiptDigest(receipt Receipt) (string, error) {
	canonical, err := cryptoinfra.CanonicalizeAny(receipt)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func computeReplayInputsDigest(input BundleInput, receipt Receipt) (string, error) {
	proof := input.Proofs[0]
	sthSignature := proof.STHSignature
	if sthSignature == "" && len(proof.STH.Signature) > 0 {
		sthSignature = base64.StdEncoding.EncodeToString(proof.STH.Signature)
	}
	if sthSignature == "" {
		return "", errors.New("sth signature is required for replay digest")
	}

	policyEval := input.PolicyEvaluation
	if policyEval == nil && receipt.Policy != nil {
		eval, err := policyEvaluationFromReceipt(receipt.Policy)
		if err != nil {
			return "", err
		}
		policyEval = &eval
	}
	decision := input.Decision
	if decision == nil {
		decision = receipt.Decision
	}

	derivation := receipt.Derivation
	if derivation == nil && input.Derivation != nil {
		derivation = derivationReceiptFromSummary(*input.Derivation)
	}

	replayBundle, err := replay.BuildReplayBundle(replay.BundleInput{
		Envelope:         input.Envelopes[0],
		STH:              proof.STH,
		STHSignature:     sthSignature,
		Inclusion:        proof.Inclusion,
		Derivation:       derivation,
		PolicyEvaluation: policyEval,
		DecisionResult:   decision,
		Engines:          input.Engines,
		RevocationEpoch:  input.RevocationEpoch,
	})
	if err != nil {
		return "", err
	}
	return replayBundle.ReplayInputsDigest, nil
}

func policyEvaluationFromReceipt(receipt domain.PolicyReceipt) (domain.PolicyEvaluation, error) {
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

func applyDefaultEngines(engines replay.EngineVersions) replay.EngineVersions {
	if engines.Verification == "" {
		engines.Verification = replay.DefaultVerificationEngineVersion
	}
	if engines.Policy == "" {
		engines.Policy = replay.DefaultPolicyEngineVersion
	}
	if engines.Decision == "" {
		engines.Decision = replay.DefaultDecisionEngineVersion
	}
	return engines
}

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}
