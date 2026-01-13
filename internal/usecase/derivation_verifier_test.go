package usecase

import (
	"context"
	"testing"
	"time"

	"proteus/internal/domain"
)

type memoryManifestReader struct {
	manifests map[string]domain.SignedManifestEnvelope
}

func (r *memoryManifestReader) GetEnvelopeByManifestID(ctx context.Context, tenantID, manifestID string) (*domain.SignedManifestEnvelope, error) {
	env, ok := r.manifests[manifestID]
	if !ok || env.Manifest.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	copyEnv := env
	return &copyEnv, nil
}

type memoryProvenanceRepo struct {
	generated map[string][]string
}

func (r *memoryProvenanceRepo) UpsertArtifact(ctx context.Context, tenantID string, artifact domain.Artifact) (string, error) {
	return "artifact-id", nil
}

func (r *memoryProvenanceRepo) AddEdge(ctx context.Context, edge domain.ProvenanceEdge) error {
	return nil
}

func (r *memoryProvenanceRepo) ListGeneratedManifestIDs(ctx context.Context, tenantID string, hash domain.Hash) ([]string, error) {
	ids := r.generated[provKey(tenantID, hash)]
	out := make([]string, len(ids))
	copy(out, ids)
	return out, nil
}

func provKey(tenantID string, hash domain.Hash) string {
	return tenantID + "|" + hash.Alg + "|" + hash.Value
}

func TestDerivationVerifier_CompleteChain(t *testing.T) {
	tenantID := "tenant-1"
	rootID := "manifest-root"
	childID := "manifest-child"
	inputHash := domain.Hash{Alg: "sha256", Value: "deadbeef"}

	rootEnv := domain.SignedManifestEnvelope{
		Manifest: makeManifest(tenantID, rootID, []domain.InputArtifact{
			{MediaType: "text/plain", Hash: inputHash},
		}),
	}
	childEnv := domain.SignedManifestEnvelope{
		Manifest: makeManifest(tenantID, childID, nil),
	}

	verifier := &DerivationVerifier{
		Manifests: &memoryManifestReader{
			manifests: map[string]domain.SignedManifestEnvelope{
				rootID:  rootEnv,
				childID: childEnv,
			},
		},
		Provenance: &memoryProvenanceRepo{
			generated: map[string][]string{
				provKey(tenantID, inputHash): {childID},
			},
		},
	}

	summary, err := verifier.Verify(context.Background(), tenantID, rootID)
	if err != nil {
		t.Fatalf("verify derivation: %v", err)
	}
	if !summary.Complete {
		t.Fatalf("expected complete derivation")
	}
	if summary.Depth != 1 {
		t.Fatalf("expected depth 1, got %d", summary.Depth)
	}
	if summary.Severity != domain.DerivationSeverityNone {
		t.Fatalf("expected severity none, got %s", summary.Severity)
	}
	if len(summary.Failures) != 0 {
		t.Fatalf("expected no failures, got %d", len(summary.Failures))
	}
}

func TestDerivationVerifier_MissingInput(t *testing.T) {
	tenantID := "tenant-1"
	rootID := "manifest-root"
	inputHash := domain.Hash{Alg: "sha256", Value: "missing"}

	rootEnv := domain.SignedManifestEnvelope{
		Manifest: makeManifest(tenantID, rootID, []domain.InputArtifact{
			{MediaType: "text/plain", Hash: inputHash},
		}),
	}

	verifier := &DerivationVerifier{
		Manifests: &memoryManifestReader{
			manifests: map[string]domain.SignedManifestEnvelope{
				rootID: rootEnv,
			},
		},
		Provenance: &memoryProvenanceRepo{
			generated: map[string][]string{},
		},
	}

	summary, err := verifier.Verify(context.Background(), tenantID, rootID)
	if err != nil {
		t.Fatalf("verify derivation: %v", err)
	}
	if summary.Complete {
		t.Fatalf("expected incomplete derivation")
	}
	if summary.Severity != domain.DerivationSeverityError {
		t.Fatalf("expected severity error, got %s", summary.Severity)
	}
	if summary.Depth != 0 {
		t.Fatalf("expected depth 0, got %d", summary.Depth)
	}
	if len(summary.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(summary.Failures))
	}
	if summary.Failures[0].Code != domain.DerivationFailureInputMissing {
		t.Fatalf("expected failure code %s, got %s", domain.DerivationFailureInputMissing, summary.Failures[0].Code)
	}
}

func makeManifest(tenantID, manifestID string, inputs []domain.InputArtifact) domain.Manifest {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return domain.Manifest{
		Schema:     "trust.manifest.v0",
		ManifestID: manifestID,
		TenantID:   tenantID,
		Subject: domain.Subject{
			Type:      "artifact",
			MediaType: "text/plain",
			Hash: domain.Hash{
				Alg:   "sha256",
				Value: "subject",
			},
		},
		Actor: domain.Actor{
			Type: "service",
			ID:   "svc",
		},
		Tool: domain.Tool{
			Name:    "tool",
			Version: "1.0.0",
		},
		Time: domain.ManifestTime{
			CreatedAt:   now,
			SubmittedAt: now,
		},
		Inputs: inputs,
	}
}
