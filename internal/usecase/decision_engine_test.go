package usecase

import (
	"reflect"
	"testing"

	"proteus/internal/domain"
)

func TestDecisionEngineV0_Deterministic(t *testing.T) {
	engine := &DecisionEngineV0{}
	input := DecisionInput{
		Verification: domain.PolicyVerification{
			SignatureValid: true,
			KeyStatus:      "active",
			LogIncluded:    true,
		},
		Derivation: &domain.DerivationSummary{
			Complete: false,
			Failures: []domain.DerivationFailure{
				{Code: domain.DerivationFailureInputMissing},
				{Code: domain.DerivationFailureManifestNotFound},
			},
		},
		Policy: domain.PolicyResult{
			Allow: false,
			Deny: []domain.PolicyDeny{
				{Code: "LOG_PROOF_INVALID"},
				{Code: "SIGNATURE_INVALID"},
			},
		},
	}

	first, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate decision: %v", err)
	}
	second, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate decision: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic output")
	}
	if first.Action != "deny" {
		t.Fatalf("expected action deny, got %s", first.Action)
	}
	if first.Score != 100 {
		t.Fatalf("expected score 100, got %d", first.Score)
	}
	if !isSorted(first.Reasons) {
		t.Fatalf("expected reasons to be sorted")
	}
}

func TestDecisionEngineV0_AllowNoReasons(t *testing.T) {
	engine := &DecisionEngineV0{}
	input := DecisionInput{
		Verification: domain.PolicyVerification{
			SignatureValid: true,
			KeyStatus:      "active",
			LogIncluded:    true,
		},
		Policy: domain.PolicyResult{
			Allow: true,
		},
	}

	result, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate decision: %v", err)
	}
	if result.Action != "allow" {
		t.Fatalf("expected action allow, got %s", result.Action)
	}
	if result.Score != 0 {
		t.Fatalf("expected score 0, got %d", result.Score)
	}
	if len(result.Reasons) != 0 {
		t.Fatalf("expected no reasons, got %v", result.Reasons)
	}
}

func isSorted(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}
