package policyopa

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"proteus/internal/domain"
)

func TestEngineDeterministic(t *testing.T) {
	engine := newEngine(t)
	input := basePolicyInput()

	first, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate first: %v", err)
	}
	second, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluate second: %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic policy evaluation")
	}
	if !first.Result.Allow {
		t.Fatalf("expected allow for baseline input")
	}
	if len(first.Result.Deny) != 0 {
		t.Fatalf("expected empty deny list")
	}
	if first.BundleHash == "" {
		t.Fatalf("expected bundle hash to be set")
	}
}

func TestEnginePolicyDenies(t *testing.T) {
	engine := newEngine(t)

	tests := []struct {
		name   string
		mutate func(input *domain.PolicyInput)
		want   []string
	}{
		{
			name: "signature invalid",
			mutate: func(input *domain.PolicyInput) {
				input.Verification.SignatureValid = false
			},
			want: []string{"SIGNATURE_INVALID"},
		},
		{
			name: "key revoked",
			mutate: func(input *domain.PolicyInput) {
				input.Verification.KeyStatus = "revoked"
			},
			want: []string{"KEY_REVOKED"},
		},
		{
			name: "log proof invalid",
			mutate: func(input *domain.PolicyInput) {
				input.Verification.LogIncluded = false
			},
			want: []string{"LOG_PROOF_INVALID"},
		},
		{
			name: "proof required",
			mutate: func(input *domain.PolicyInput) {
				input.Verification.LogIncluded = false
				input.Options.RequireProof = true
			},
			want: []string{"LOG_PROOF_INVALID", "PROOF_REQUIRED"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			input := basePolicyInput()
			tt.mutate(&input)
			out, err := engine.Evaluate(context.Background(), input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if out.Result.Allow {
				t.Fatalf("expected deny")
			}
			got := denyCodes(out.Result.Deny)
			for _, code := range tt.want {
				if !got[code] {
					t.Fatalf("expected deny code %s", code)
				}
			}
			if tt.name == "proof required" {
				if !reflect.DeepEqual(tt.want, denyOrder(out.Result.Deny)) {
					t.Fatalf("expected deterministic deny ordering")
				}
			}
		})
	}
}

func TestEngineRejectsTimeBuiltin(t *testing.T) {
	rejectBuiltin(t, "time.now_ns()")
}

func TestEngineRejectsHttpSend(t *testing.T) {
	rejectBuiltin(t, "http.send({\"method\": \"get\", \"url\": \"https://example.com\"})")
}

func TestEngineRejectsRand(t *testing.T) {
	rejectBuiltin(t, "rand.intn(10)")
}

func rejectBuiltin(t *testing.T, expr string) {
	t.Helper()
	dir := t.TempDir()
	regoContent := `package proteus.policy
result := {"allow": true, "deny": []} {
  ` + expr + `
}`
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(regoContent), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}

	_, err := NewEngineFromBundlePath(context.Background(), dir, "test")
	if err == nil {
		t.Fatalf("expected builtin to be rejected")
	}
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	path := filepath.Join("..", "..", "..", "policy", "bundles", "reference_v0")
	engine, err := NewEngineFromBundlePath(context.Background(), path, "reference_v0")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return engine
}

func basePolicyInput() domain.PolicyInput {
	return domain.PolicyInput{
		Envelope: domain.SignedManifestEnvelope{
			Manifest: domain.Manifest{
				Schema:     "trust.manifest.v0",
				ManifestID: "manifest-1",
				TenantID:   "tenant-1",
				Subject: domain.Subject{
					Type:      "artifact",
					MediaType: "application/json",
					Hash: domain.Hash{
						Alg:   "sha256",
						Value: "aaaa",
					},
				},
				Actor: domain.Actor{
					Type: "person",
					ID:   "actor-1",
				},
				Tool: domain.Tool{
					Name:    "tool",
					Version: "1.0.0",
				},
				Time: domain.ManifestTime{
					CreatedAt:   time.Unix(0, 0).UTC(),
					SubmittedAt: time.Unix(0, 0).UTC(),
				},
			},
			Signature: domain.Signature{
				Alg:   "ed25519",
				KID:   "kid-1",
				Value: "sig",
			},
		},
		Verification: domain.PolicyVerification{
			SignatureValid: true,
			KeyStatus:      "active",
			LogIncluded:    true,
		},
		Options: &domain.PolicyOptions{
			RequireProof: false,
		},
	}
}

func denyCodes(deny []domain.PolicyDeny) map[string]bool {
	out := make(map[string]bool, len(deny))
	for _, item := range deny {
		out[item.Code] = true
	}
	return out
}

func denyOrder(deny []domain.PolicyDeny) []string {
	out := make([]string, 0, len(deny))
	for _, item := range deny {
		out = append(out, item.Code)
	}
	return out
}
