package usecase

import (
	"context"
	"testing"
	"time"

	"proteus/internal/domain"
)

func TestProvenanceQuery_LineageMultiHop(t *testing.T) {
	tenantID := "tenant-1"
	rootHash := domain.Hash{Alg: "sha256", Value: "root"}
	midHash := domain.Hash{Alg: "sha256", Value: "mid"}
	leafHash := domain.Hash{Alg: "sha256", Value: "leaf"}

	rootID := "manifest-root"
	midID := "manifest-mid"
	leafID := "manifest-leaf"

	reader := &memoryManifestReader{manifests: map[string]domain.SignedManifestEnvelope{
		rootID: {Manifest: makeManifestWithSubject(tenantID, rootID, rootHash, []domain.InputArtifact{{MediaType: "text/plain", Hash: midHash}})},
		midID:  {Manifest: makeManifestWithSubject(tenantID, midID, midHash, []domain.InputArtifact{{MediaType: "text/plain", Hash: leafHash}})},
		leafID: {Manifest: makeManifestWithSubject(tenantID, leafID, leafHash, nil)},
	}}

	repo := &memoryProvenanceRepo{
		generated: map[string][]string{
			provKey(tenantID, rootHash): {rootID},
			provKey(tenantID, midHash):  {midID},
			provKey(tenantID, leafHash): {leafID},
		},
		artifacts: map[string]domain.Artifact{
			provKey(tenantID, rootHash): {TenantID: tenantID, Hash: rootHash, MediaType: "text/plain"},
			provKey(tenantID, midHash):  {TenantID: tenantID, Hash: midHash, MediaType: "text/plain"},
			provKey(tenantID, leafHash): {TenantID: tenantID, Hash: leafHash, MediaType: "text/plain"},
		},
	}

	query := &ProvenanceQuery{Manifests: reader, Provenance: repo}
	result, err := query.Lineage(context.Background(), tenantID, rootHash, LineageOptions{MaxDepth: 10, MaxNodes: 100})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if !result.Complete {
		t.Fatalf("expected complete lineage")
	}
	if result.Truncated {
		t.Fatalf("expected non-truncated lineage")
	}
	if result.Depth != 2 {
		t.Fatalf("expected depth 2, got %d", result.Depth)
	}
	if len(result.GeneratingManifests) != 1 {
		t.Fatalf("expected 1 generating manifest, got %d", len(result.GeneratingManifests))
	}
	if result.GeneratingManifests[0].ManifestID != rootID {
		t.Fatalf("expected root manifest %s, got %s", rootID, result.GeneratingManifests[0].ManifestID)
	}
	if len(result.MissingArtifacts) != 0 || len(result.MissingManifests) != 0 {
		t.Fatalf("expected no missing items")
	}
}

func TestProvenanceQuery_LineageMissingArtifact(t *testing.T) {
	tenantID := "tenant-1"
	hash := domain.Hash{Alg: "sha256", Value: "missing"}

	query := &ProvenanceQuery{
		Manifests:  &memoryManifestReader{manifests: map[string]domain.SignedManifestEnvelope{}},
		Provenance: &memoryProvenanceRepo{generated: map[string][]string{}},
	}

	result, err := query.Lineage(context.Background(), tenantID, hash, LineageOptions{MaxDepth: 10, MaxNodes: 100})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if result.Complete {
		t.Fatalf("expected incomplete lineage")
	}
	if result.Truncated {
		t.Fatalf("expected non-truncated lineage")
	}
	if len(result.MissingArtifacts) != 1 {
		t.Fatalf("expected missing artifact reported")
	}
	if result.MissingArtifacts[0].Value != hash.Value {
		t.Fatalf("expected missing artifact %s, got %s", hash.Value, result.MissingArtifacts[0].Value)
	}
}

func TestProvenanceQuery_Derivation(t *testing.T) {
	tenantID := "tenant-1"
	manifestID := "manifest-1"
	inputHash := domain.Hash{Alg: "sha256", Value: "input"}
	outputHash := domain.Hash{Alg: "sha256", Value: "output"}

	reader := &memoryManifestReader{manifests: map[string]domain.SignedManifestEnvelope{
		manifestID: {
			Manifest: makeManifestWithSubject(tenantID, manifestID, outputHash, []domain.InputArtifact{{MediaType: "text/plain", Hash: inputHash}}),
			Signature: domain.Signature{
				Alg: "ed25519",
				KID: "kid-1",
			},
		},
	}}

	query := &ProvenanceQuery{Manifests: reader, Provenance: &memoryProvenanceRepo{}}
	result, err := query.Derivation(context.Background(), tenantID, manifestID, LineageOptions{MaxDepth: 10, MaxNodes: 100})
	if err != nil {
		t.Fatalf("derivation query: %v", err)
	}
	if result.ManifestID != manifestID {
		t.Fatalf("expected manifest_id %s, got %s", manifestID, result.ManifestID)
	}
	if result.SignerKID != "kid-1" {
		t.Fatalf("expected signer kid-1, got %s", result.SignerKID)
	}
	if len(result.Inputs) != 1 || result.Inputs[0].Value != inputHash.Value {
		t.Fatalf("expected input hash %s", inputHash.Value)
	}
	if len(result.Outputs) != 1 || result.Outputs[0].Value != outputHash.Value {
		t.Fatalf("expected output hash %s", outputHash.Value)
	}
	if result.Truncated {
		t.Fatalf("expected derivation non-truncated")
	}
}

func TestProvenanceQuery_LineageMaxDepthTruncation(t *testing.T) {
	tenantID := "tenant-1"
	rootHash := domain.Hash{Alg: "sha256", Value: "root"}
	midHash := domain.Hash{Alg: "sha256", Value: "mid"}
	leafHash := domain.Hash{Alg: "sha256", Value: "leaf"}
	rootID := "manifest-root"
	midID := "manifest-mid"
	leafID := "manifest-leaf"

	reader := &memoryManifestReader{manifests: map[string]domain.SignedManifestEnvelope{
		rootID: {Manifest: makeManifestWithSubject(tenantID, rootID, rootHash, []domain.InputArtifact{{MediaType: "text/plain", Hash: midHash}})},
		midID:  {Manifest: makeManifestWithSubject(tenantID, midID, midHash, []domain.InputArtifact{{MediaType: "text/plain", Hash: leafHash}})},
		leafID: {Manifest: makeManifestWithSubject(tenantID, leafID, leafHash, nil)},
	}}

	repo := &memoryProvenanceRepo{
		generated: map[string][]string{
			provKey(tenantID, rootHash): {rootID},
			provKey(tenantID, midHash):  {midID},
			provKey(tenantID, leafHash): {leafID},
		},
		artifacts: map[string]domain.Artifact{
			provKey(tenantID, rootHash): {TenantID: tenantID, Hash: rootHash, MediaType: "text/plain"},
			provKey(tenantID, midHash):  {TenantID: tenantID, Hash: midHash, MediaType: "text/plain"},
			provKey(tenantID, leafHash): {TenantID: tenantID, Hash: leafHash, MediaType: "text/plain"},
		},
	}

	query := &ProvenanceQuery{Manifests: reader, Provenance: repo}
	result, err := query.Lineage(context.Background(), tenantID, rootHash, LineageOptions{MaxDepth: 1, MaxNodes: 100})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if !result.Truncated {
		t.Fatalf("expected truncated lineage")
	}
	if !contains(result.Limits.Hit, "max_depth") {
		t.Fatalf("expected max_depth truncation")
	}
}

func TestProvenanceQuery_LineageMaxNodesTruncation(t *testing.T) {
	tenantID := "tenant-1"
	hash := domain.Hash{Alg: "sha256", Value: "root"}
	rootID := "manifest-root"

	reader := &memoryManifestReader{manifests: map[string]domain.SignedManifestEnvelope{
		rootID: {Manifest: makeManifestWithSubject(tenantID, rootID, hash, nil)},
	}}
	repo := &memoryProvenanceRepo{
		generated: map[string][]string{
			provKey(tenantID, hash): {rootID},
		},
		artifacts: map[string]domain.Artifact{
			provKey(tenantID, hash): {TenantID: tenantID, Hash: hash, MediaType: "text/plain"},
		},
	}

	query := &ProvenanceQuery{Manifests: reader, Provenance: repo}
	result, err := query.Lineage(context.Background(), tenantID, hash, LineageOptions{MaxDepth: 10, MaxNodes: 0})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if result.Truncated {
		t.Fatalf("expected no truncation with max_nodes=0")
	}

	result, err = query.Lineage(context.Background(), tenantID, hash, LineageOptions{MaxDepth: 10, MaxNodes: 1})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if result.Truncated {
		t.Fatalf("expected no truncation for single node with max_nodes=1")
	}

	secondID := "manifest-second"
	reader.manifests[secondID] = domain.SignedManifestEnvelope{
		Manifest: makeManifestWithSubject(tenantID, secondID, domain.Hash{Alg: "sha256", Value: "child"}, nil),
	}
	repo.generated[provKey(tenantID, hash)] = []string{rootID, secondID}
	repo.artifacts[provKey(tenantID, domain.Hash{Alg: "sha256", Value: "child"})] = domain.Artifact{TenantID: tenantID, Hash: domain.Hash{Alg: "sha256", Value: "child"}, MediaType: "text/plain"}

	result, err = query.Lineage(context.Background(), tenantID, hash, LineageOptions{MaxDepth: 10, MaxNodes: 1})
	if err != nil {
		t.Fatalf("lineage query: %v", err)
	}
	if !result.Truncated {
		t.Fatalf("expected truncation with max_nodes=1")
	}
	if !contains(result.Limits.Hit, "max_nodes") {
		t.Fatalf("expected max_nodes truncation")
	}
}

func makeManifestWithSubject(tenantID, manifestID string, subjectHash domain.Hash, inputs []domain.InputArtifact) domain.Manifest {
	now := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	manifest := makeManifest(tenantID, manifestID, inputs)
	manifest.Subject.Hash = subjectHash
	manifest.Time = domain.ManifestTime{CreatedAt: now, SubmittedAt: now}
	return manifest
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
