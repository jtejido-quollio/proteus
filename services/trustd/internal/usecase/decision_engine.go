package usecase

import (
	"sort"
	"strings"

	"proteus/internal/domain"
)

const DecisionEngineVersion = "decision.v0.0.1"

type DecisionInput struct {
	Verification    domain.PolicyVerification
	Derivation      *domain.DerivationSummary
	Policy          domain.PolicyResult
	RevocationEpoch int64
}

type DecisionResult struct {
	EngineVersion string
	Score         int
	Action        string
	Reasons       []string
}

type DecisionEngineV0 struct{}

func (e *DecisionEngineV0) Evaluate(input DecisionInput) (DecisionResult, error) {
	reasons := make(map[string]struct{})
	addReason(reasons, verificationReasons(input.Verification)...)
	addReason(reasons, policyReasons(input.Policy)...)
	addReason(reasons, derivationReasons(input.Derivation)...)

	ordered := sortedReasons(reasons)
	action := "allow"
	score := 0
	if !input.Policy.Allow {
		action = "block"
		score = 100
	} else if input.Derivation != nil && !input.Derivation.Complete {
		action = "require_review"
		score = 50
	}

	return DecisionResult{
		EngineVersion: DecisionEngineVersion,
		Score:         score,
		Action:        action,
		Reasons:       ordered,
	}, nil
}

func verificationReasons(verification domain.PolicyVerification) []string {
	var reasons []string
	if !verification.SignatureValid {
		reasons = append(reasons, "SIGNATURE_INVALID")
	}
	switch strings.ToLower(verification.KeyStatus) {
	case string(domain.KeyStatusRevoked):
		reasons = append(reasons, "KEY_REVOKED")
	case string(domain.KeyStatusRetired):
		reasons = append(reasons, "KEY_RETIRED")
	}
	if !verification.LogIncluded {
		reasons = append(reasons, "LOG_PROOF_INVALID")
	}
	if verification.ArtifactHashValid != nil && !*verification.ArtifactHashValid {
		reasons = append(reasons, "ARTIFACT_HASH_MISMATCH")
	}
	return reasons
}

func policyReasons(policy domain.PolicyResult) []string {
	reasons := make([]string, 0, len(policy.Deny))
	for _, deny := range policy.Deny {
		if deny.Code != "" {
			reasons = append(reasons, deny.Code)
		}
	}
	if !policy.Allow && len(reasons) == 0 {
		reasons = append(reasons, "POLICY_DENY")
	}
	return reasons
}

func derivationReasons(summary *domain.DerivationSummary) []string {
	if summary == nil || summary.Complete {
		return nil
	}
	reasons := make([]string, 0, len(summary.Failures))
	for _, failure := range summary.Failures {
		if failure.Code != "" {
			reasons = append(reasons, failure.Code)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "DERIVATION_INCOMPLETE")
	}
	return reasons
}

func addReason(reasonSet map[string]struct{}, reasons ...string) {
	for _, reason := range reasons {
		if reason == "" {
			continue
		}
		reasonSet[reason] = struct{}{}
	}
}

func sortedReasons(reasons map[string]struct{}) []string {
	if len(reasons) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(reasons))
	for reason := range reasons {
		ordered = append(ordered, reason)
	}
	sort.Strings(ordered)
	return ordered
}
