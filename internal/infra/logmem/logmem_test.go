package logmem

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type inclusionVector struct {
	LeafHash    string   `json:"leaf_hash"`
	LeafIndex   int      `json:"leaf_index"`
	Path        []string `json:"path"`
	STHRootHash string   `json:"sth_root_hash"`
	STHTreeSize int      `json:"sth_tree_size"`
	TenantID    string   `json:"tenant_id"`
}

type consistencyVector struct {
	FromSize int      `json:"from_size"`
	ToSize   int      `json:"to_size"`
	Path     []string `json:"path"`
	TenantID string   `json:"tenant_id"`
}

func TestTenantLogInclusionVectorTreeSize4(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "inclusion_proof_leaf_index_2.json"))
	var vec inclusionVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal inclusion proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	log := New()
	ctx := context.Background()
	for _, leaf := range leaves[:vec.STHTreeSize] {
		if _, _, _, err := log.AppendLeaf(ctx, vec.TenantID, "signed-id", leaf); err != nil {
			t.Fatalf("append leaf: %v", err)
		}
	}

	leafHash := decodeHex(t, vec.LeafHash)
	leafIndex, sth, inclusion, err := log.GetInclusionProof(ctx, vec.TenantID, leafHash)
	if err != nil {
		t.Fatalf("get inclusion proof: %v", err)
	}
	if leafIndex != int64(vec.LeafIndex) {
		t.Fatalf("unexpected leaf index: %d", leafIndex)
	}
	if sth.TreeSize != int64(vec.STHTreeSize) {
		t.Fatalf("unexpected sth tree size: %d", sth.TreeSize)
	}
	expectedRoot := decodeHex(t, vec.STHRootHash)
	if !bytes.Equal(sth.RootHash, expectedRoot) {
		t.Fatal("sth root hash mismatch")
	}

	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(inclusion.Path, expectedPath) {
		t.Fatal("inclusion proof path mismatch")
	}
	if inclusion.STHTreeSize != int64(vec.STHTreeSize) {
		t.Fatalf("unexpected inclusion tree size: %d", inclusion.STHTreeSize)
	}
	if !bytes.Equal(inclusion.STHRootHash, expectedRoot) {
		t.Fatal("inclusion root hash mismatch")
	}
}

func TestTenantLogInclusionVectorTreeSize3(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "inclusion_proof_leaf_index_2_tree_size_3.json"))
	var vec inclusionVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal inclusion proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	log := New()
	ctx := context.Background()
	for _, leaf := range leaves[:vec.STHTreeSize] {
		if _, _, _, err := log.AppendLeaf(ctx, vec.TenantID, "signed-id", leaf); err != nil {
			t.Fatalf("append leaf: %v", err)
		}
	}

	leafHash := decodeHex(t, vec.LeafHash)
	leafIndex, sth, inclusion, err := log.GetInclusionProof(ctx, vec.TenantID, leafHash)
	if err != nil {
		t.Fatalf("get inclusion proof: %v", err)
	}
	if leafIndex != int64(vec.LeafIndex) {
		t.Fatalf("unexpected leaf index: %d", leafIndex)
	}
	expectedRoot := decodeHex(t, vec.STHRootHash)
	if !bytes.Equal(sth.RootHash, expectedRoot) {
		t.Fatal("sth root hash mismatch")
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(inclusion.Path, expectedPath) {
		t.Fatal("inclusion proof path mismatch")
	}
}

func TestTenantLogConsistencyVectorFrom3To4(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "consistency_proof_from_3_to_4.json"))
	var vec consistencyVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal consistency proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	log := New()
	ctx := context.Background()
	for _, leaf := range leaves[:vec.ToSize] {
		if _, _, _, err := log.AppendLeaf(ctx, vec.TenantID, "signed-id", leaf); err != nil {
			t.Fatalf("append leaf: %v", err)
		}
	}

	proof, err := log.GetConsistencyProof(ctx, vec.TenantID, int64(vec.FromSize), int64(vec.ToSize))
	if err != nil {
		t.Fatalf("get consistency proof: %v", err)
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(proof.Path, expectedPath) {
		t.Fatal("consistency proof path mismatch")
	}
	if proof.FromSize != int64(vec.FromSize) || proof.ToSize != int64(vec.ToSize) {
		t.Fatal("consistency proof size mismatch")
	}
}

func TestTenantLogIdempotentAppend(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	leaves := loadLeafHashes(t, vectorsDir)
	if len(leaves) == 0 {
		t.Fatal("no leaves")
	}
	log := New()
	ctx := context.Background()

	index1, sth1, inclusion1, err := log.AppendLeaf(ctx, "tenant", "signed-1", leaves[0])
	if err != nil {
		t.Fatalf("append leaf: %v", err)
	}
	index2, sth2, inclusion2, err := log.AppendLeaf(ctx, "tenant", "signed-1", leaves[0])
	if err != nil {
		t.Fatalf("append leaf again: %v", err)
	}
	if index1 != index2 {
		t.Fatalf("expected same leaf index, got %d vs %d", index1, index2)
	}
	if sth1.TreeSize != sth2.TreeSize || !bytes.Equal(sth1.RootHash, sth2.RootHash) {
		t.Fatal("expected idempotent STH")
	}
	if inclusion1.LeafIndex != inclusion2.LeafIndex || inclusion1.STHTreeSize != inclusion2.STHTreeSize {
		t.Fatal("expected idempotent inclusion proof")
	}
	if !hashPathEqual(inclusion1.Path, inclusion2.Path) {
		t.Fatal("expected identical inclusion path")
	}
}

func loadLeafHashes(t *testing.T, vectorsDir string) [][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(vectorsDir, "leaf_*.sha256.hex"))
	if err != nil {
		t.Fatalf("glob leaf hashes: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no leaf hashes found")
	}
	sort.Strings(files)

	leaves := make([][]byte, 0, len(files))
	for _, path := range files {
		hexStr := strings.TrimSpace(string(readFile(t, path)))
		leaves = append(leaves, decodeHex(t, hexStr))
	}
	return leaves
}

func decodeHexPath(t *testing.T, values []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(values))
	for _, val := range values {
		out = append(out, decodeHex(t, val))
	}
	return out
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func hashPathEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
