package merkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
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
}

type consistencyVector struct {
	FromSize int      `json:"from_size"`
	ToSize   int      `json:"to_size"`
	Path     []string `json:"path"`
}

func TestInclusionProofVector(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "inclusion_proof_leaf_index_2.json"))
	var vec inclusionVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal inclusion proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	path, err := InclusionProof(leaves, vec.LeafIndex)
	if err != nil {
		t.Fatalf("generate inclusion proof: %v", err)
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(path, expectedPath) {
		t.Fatal("inclusion proof path mismatch")
	}

	root, err := Root(leaves[:vec.STHTreeSize])
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	expectedRoot := decodeHex(t, vec.STHRootHash)
	if !bytes.Equal(root, expectedRoot) {
		t.Fatal("root hash mismatch")
	}

	ok, err := VerifyInclusionProof(decodeHex(t, vec.LeafHash), vec.LeafIndex, vec.STHTreeSize, path, root)
	if err != nil {
		t.Fatalf("verify inclusion proof: %v", err)
	}
	if !ok {
		t.Fatal("expected inclusion proof to verify")
	}
}

func TestInclusionProofVectorTreeSize3(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "inclusion_proof_leaf_index_2_tree_size_3.json"))
	var vec inclusionVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal inclusion proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	path, err := InclusionProof(leaves[:vec.STHTreeSize], vec.LeafIndex)
	if err != nil {
		t.Fatalf("generate inclusion proof: %v", err)
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(path, expectedPath) {
		t.Fatal("inclusion proof path mismatch")
	}

	root, err := Root(leaves[:vec.STHTreeSize])
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	expectedRoot := decodeHex(t, vec.STHRootHash)
	if !bytes.Equal(root, expectedRoot) {
		t.Fatal("root hash mismatch")
	}

	ok, err := VerifyInclusionProof(decodeHex(t, vec.LeafHash), vec.LeafIndex, vec.STHTreeSize, path, root)
	if err != nil {
		t.Fatalf("verify inclusion proof: %v", err)
	}
	if !ok {
		t.Fatal("expected inclusion proof to verify")
	}
}

func TestConsistencyProofVector(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "consistency_proof_from_2_to_4.json"))
	var vec consistencyVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal consistency proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	path, err := ConsistencyProof(leaves, vec.FromSize, vec.ToSize)
	if err != nil {
		t.Fatalf("generate consistency proof: %v", err)
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(path, expectedPath) {
		t.Fatal("consistency proof path mismatch")
	}

	oldRoot, err := Root(leaves[:vec.FromSize])
	if err != nil {
		t.Fatalf("compute old root: %v", err)
	}
	newRoot, err := Root(leaves[:vec.ToSize])
	if err != nil {
		t.Fatalf("compute new root: %v", err)
	}

	ok, err := VerifyConsistencyProof(oldRoot, newRoot, vec.FromSize, vec.ToSize, path)
	if err != nil {
		t.Fatalf("verify consistency proof: %v", err)
	}
	if !ok {
		t.Fatal("expected consistency proof to verify")
	}
}

func TestConsistencyProofVectorFrom3To4(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "consistency_proof_from_3_to_4.json"))
	var vec consistencyVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal consistency proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	path, err := ConsistencyProof(leaves, vec.FromSize, vec.ToSize)
	if err != nil {
		t.Fatalf("generate consistency proof: %v", err)
	}
	expectedPath := decodeHexPath(t, vec.Path)
	if !hashPathEqual(path, expectedPath) {
		t.Fatal("consistency proof path mismatch")
	}

	oldRoot, err := Root(leaves[:vec.FromSize])
	if err != nil {
		t.Fatalf("compute old root: %v", err)
	}
	newRoot, err := Root(leaves[:vec.ToSize])
	if err != nil {
		t.Fatalf("compute new root: %v", err)
	}

	ok, err := VerifyConsistencyProof(oldRoot, newRoot, vec.FromSize, vec.ToSize, path)
	if err != nil {
		t.Fatalf("verify consistency proof: %v", err)
	}
	if !ok {
		t.Fatal("expected consistency proof to verify")
	}
}

func TestConsistencyProofNegativeCases(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	vectorBytes := readFile(t, filepath.Join(vectorsDir, "consistency_proof_from_3_to_4.json"))
	var vec consistencyVector
	if err := json.Unmarshal(vectorBytes, &vec); err != nil {
		t.Fatalf("unmarshal consistency proof: %v", err)
	}

	leaves := loadLeafHashes(t, vectorsDir)
	expectedPath := decodeHexPath(t, vec.Path)
	oldRoot, err := Root(leaves[:vec.FromSize])
	if err != nil {
		t.Fatalf("compute old root: %v", err)
	}
	newRoot, err := Root(leaves[:vec.ToSize])
	if err != nil {
		t.Fatalf("compute new root: %v", err)
	}

	ok, err := VerifyConsistencyProof(newRoot, oldRoot, vec.FromSize, vec.ToSize, expectedPath)
	if err != nil {
		t.Fatalf("verify consistency proof with swapped roots: %v", err)
	}
	if ok {
		t.Fatal("expected swapped roots to fail")
	}

	if len(expectedPath) == 0 {
		t.Fatal("expected non-empty consistency proof path")
	}
	tampered := clonePath(expectedPath)
	tampered[0][0] ^= 0x01
	ok, err = VerifyConsistencyProof(oldRoot, newRoot, vec.FromSize, vec.ToSize, tampered)
	if err != nil {
		t.Fatalf("verify tampered consistency proof: %v", err)
	}
	if ok {
		t.Fatal("expected tampered path[0] to fail")
	}

	ok, err = VerifyConsistencyProof(oldRoot, newRoot, vec.FromSize+1, vec.ToSize, expectedPath)
	if err != nil && !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("verify consistency proof with modified from_size: %v", err)
	}
	if err == nil && ok {
		t.Fatal("expected modified from_size to fail")
	}

	ok, err = VerifyConsistencyProof(oldRoot, newRoot, vec.FromSize, vec.ToSize-1, expectedPath)
	if err != nil && !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("verify consistency proof with modified to_size: %v", err)
	}
	if err == nil && ok {
		t.Fatal("expected modified to_size to fail")
	}
}

func TestRandomizedInclusionProofs(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for size := 1; size <= 10; size++ {
		leaves := randomLeaves(rng, size)
		root, err := Root(leaves)
		if err != nil {
			t.Fatalf("compute root: %v", err)
		}

		for i := 0; i < size; i++ {
			path, err := InclusionProof(leaves, i)
			if err != nil {
				t.Fatalf("generate inclusion proof: %v", err)
			}
			ok, err := VerifyInclusionProof(leaves[i], i, size, path, root)
			if err != nil {
				t.Fatalf("verify inclusion proof: %v", err)
			}
			if !ok {
				t.Fatalf("inclusion proof failed for size=%d index=%d", size, i)
			}

			if len(path) > 0 {
				tampered := clonePath(path)
				tampered[0][0] ^= 0x01
				ok, err := VerifyInclusionProof(leaves[i], i, size, tampered, root)
				if err != nil {
					t.Fatalf("verify tampered proof: %v", err)
				}
				if ok {
					t.Fatalf("expected tampered proof to fail for size=%d index=%d", size, i)
				}
			}
		}
	}
}

func TestRandomizedConsistencyProofs(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for size := 1; size <= 8; size++ {
		leaves := randomLeaves(rng, size)
		for from := 1; from <= size; from++ {
			path, err := ConsistencyProof(leaves, from, size)
			if err != nil {
				t.Fatalf("generate consistency proof: %v", err)
			}
			oldRoot, err := Root(leaves[:from])
			if err != nil {
				t.Fatalf("compute old root: %v", err)
			}
			newRoot, err := Root(leaves[:size])
			if err != nil {
				t.Fatalf("compute new root: %v", err)
			}
			ok, err := VerifyConsistencyProof(oldRoot, newRoot, from, size, path)
			if err != nil {
				t.Fatalf("verify consistency proof: %v", err)
			}
			if !ok {
				t.Fatalf("consistency proof failed for from=%d size=%d", from, size)
			}

			if len(path) > 0 {
				tampered := clonePath(path)
				tampered[len(tampered)-1][0] ^= 0x01
				ok, err := VerifyConsistencyProof(oldRoot, newRoot, from, size, tampered)
				if err != nil {
					t.Fatalf("verify tampered proof: %v", err)
				}
				if ok {
					t.Fatalf("expected tampered consistency proof to fail for from=%d size=%d", from, size)
				}
			}
		}
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

func randomLeaves(rng *rand.Rand, count int) [][]byte {
	leaves := make([][]byte, count)
	for i := 0; i < count; i++ {
		leaf := make([]byte, HashSize)
		for j := 0; j < HashSize; j++ {
			leaf[j] = byte(rng.Intn(256))
		}
		leaves[i] = leaf
	}
	return leaves
}

func clonePath(path [][]byte) [][]byte {
	out := make([][]byte, len(path))
	for i, h := range path {
		out[i] = cloneHash(h)
	}
	return out
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
