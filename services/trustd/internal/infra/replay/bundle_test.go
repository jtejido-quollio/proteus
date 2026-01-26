package replay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"
)

type sthVector struct {
	IssuedAt string `json:"issued_at"`
	RootHash string `json:"root_hash"`
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
}

type inclusionVector struct {
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
	TenantID    string   `json:"tenant_id"`
}

func TestReplayBundleMarshalDeterministic(t *testing.T) {
	env := loadEnvelope(t, "envelope_3.json")
	sth, signature := loadSTH(t)
	inclusion := loadInclusion(t, "inclusion_proof_leaf_index_2.json")

	policyBundle := map[string]any{"rules": []any{"allow"}, "version": "v1"}
	hash, err := ComputePolicyBundleHash(policyBundle)
	if err != nil {
		t.Fatalf("policy bundle hash: %v", err)
	}

	inputA := BundleInput{
		Envelope:         env,
		STH:              sth,
		STHSignature:     signature,
		Inclusion:        inclusion,
		PolicyBundleHash: hash,
		PolicyResult:     domain.PolicyReceipt{"b": "two", "a": "one"},
		Engines: EngineVersions{
			Verification: "verify@v0",
			Policy:       "opa@v0",
			Decision:     "decision@v0",
		},
	}
	bundleA, err := BuildReplayBundle(inputA)
	if err != nil {
		t.Fatalf("build bundle A: %v", err)
	}
	outA, err := MarshalBundle(bundleA)
	if err != nil {
		t.Fatalf("marshal bundle A: %v", err)
	}

	inputB := inputA
	inputB.PolicyResult = domain.PolicyReceipt{"a": "one", "b": "two"}
	bundleB, err := BuildReplayBundle(inputB)
	if err != nil {
		t.Fatalf("build bundle B: %v", err)
	}
	outB, err := MarshalBundle(bundleB)
	if err != nil {
		t.Fatalf("marshal bundle B: %v", err)
	}

	if !bytes.Equal(outA, outB) {
		t.Fatalf("expected deterministic bundle output")
	}
}

func loadEnvelope(t *testing.T, name string) domain.SignedManifestEnvelope {
	t.Helper()
	var env domain.SignedManifestEnvelope
	if err := json.Unmarshal(readVectorFile(t, name), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}

func loadSTH(t *testing.T) (domain.STH, string) {
	t.Helper()
	var vec sthVector
	if err := json.Unmarshal(readVectorFile(t, "sth.json"), &vec); err != nil {
		t.Fatalf("decode sth: %v", err)
	}
	rootHash := decodeHex(t, vec.RootHash)
	issuedAt, err := time.Parse(time.RFC3339, vec.IssuedAt)
	if err != nil {
		t.Fatalf("parse issued_at: %v", err)
	}
	signature := strings.TrimSpace(string(readVectorFile(t, "sth.signature.b64")))
	return domain.STH{
		TenantID: vec.TenantID,
		TreeSize: vec.TreeSize,
		RootHash: rootHash,
		IssuedAt: issuedAt.UTC(),
	}, signature
}

func loadInclusion(t *testing.T, name string) domain.InclusionProof {
	t.Helper()
	var vec inclusionVector
	if err := json.Unmarshal(readVectorFile(t, name), &vec); err != nil {
		t.Fatalf("decode inclusion proof: %v", err)
	}
	path := make([][]byte, 0, len(vec.Path))
	for _, node := range vec.Path {
		path = append(path, decodeHex(t, node))
	}
	return domain.InclusionProof{
		TenantID:    vec.TenantID,
		LeafIndex:   vec.LeafIndex,
		Path:        path,
		STHTreeSize: vec.STHTreeSize,
		STHRootHash: decodeHex(t, vec.STHRootHash),
	}
}

func readVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testvectors", "v0", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector %s: %v", name, err)
	}
	return data
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return data
}
