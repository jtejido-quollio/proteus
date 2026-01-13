package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proteus/internal/domain"
	"proteus/internal/infra/crypto"
	"proteus/internal/infra/merkle"
	"proteus/internal/infra/policyopa"
	"proteus/internal/usecase"
)

func runBundleVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "bundle verify requires <evidence_bundle.json>")
		return 1
	}

	path := args[0]
	payload, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read bundle: %v\n", err)
		return 1
	}

	var bundle usecase.EvidenceBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "decode bundle: %v\n", err)
		return 1
	}

	policyPath := filepath.Join("policy", "bundles", "reference_v0")
	policyEngine, err := policyopa.NewEngineFromBundlePath(context.Background(), policyPath, "reference_v0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policy bundle: %v\n", err)
		return 1
	}

	verifier := &usecase.VerifyEvidenceBundle{
		Crypto:   &crypto.Service{},
		Merkle:   &merkle.Service{},
		Policy:   policyEngine,
		Decision: &usecase.DecisionEngineV0{},
	}
	result, err := verifier.Execute(context.Background(), bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify evidence bundle: %v\n", err)
		return 1
	}

	printOutcome(bundle, result)
	if result.Passed {
		return 0
	}
	return 1
}

func printOutcome(bundle usecase.EvidenceBundle, result usecase.EvidenceVerificationResult) {
	status := "pass"
	if !result.Passed {
		status = "fail"
	}
	fmt.Printf("status=%s\n", status)
	if len(result.Failures) > 0 {
		fmt.Printf("failures=%s\n", strings.Join(result.Failures, ","))
	}

	if info, ok := decisionSummary(bundle.Receipt.Decision); ok {
		reasons := strings.Join(info.Reasons, ",")
		fmt.Printf("decision.action=%s score=%d engine=%s reasons=%s\n", info.Action, info.Score, info.EngineVersion, reasons)
	}

	bundleID, bundleHash := policyIdentity(bundle.Receipt.Policy)
	if bundleID != "" || bundleHash != "" {
		fmt.Printf("policy.bundle_id=%s policy.bundle_hash=%s\n", bundleID, bundleHash)
	}
}

type decisionInfo struct {
	EngineVersion string   `json:"engine_version"`
	Action        string   `json:"action"`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons,omitempty"`
}

func decisionSummary(receipt domain.DecisionReceipt) (decisionInfo, bool) {
	if receipt == nil {
		return decisionInfo{}, false
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return decisionInfo{}, false
	}
	var out decisionInfo
	if err := json.Unmarshal(payload, &out); err != nil {
		return decisionInfo{}, false
	}
	return out, true
}

func policyIdentity(receipt domain.PolicyReceipt) (string, string) {
	if receipt == nil {
		return "", ""
	}
	bundleID, _ := receipt["bundle_id"].(string)
	bundleHash, _ := receipt["bundle_hash"].(string)
	return bundleID, bundleHash
}
