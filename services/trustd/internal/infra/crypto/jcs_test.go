package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestCanonicalizeJSON_ManifestVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	manifestFiles, err := filepath.Glob(filepath.Join(vectorsDir, "manifest_*.json"))
	if err != nil {
		t.Fatalf("glob manifest vectors: %v", err)
	}
	if len(manifestFiles) == 0 {
		t.Fatal("no manifest vectors found")
	}
	sort.Strings(manifestFiles)

	for _, jsonPath := range manifestFiles {
		t.Run(filepath.Base(jsonPath), func(t *testing.T) {
			expectedPath := strings.TrimSuffix(jsonPath, ".json") + ".jcs"
			input := readFile(t, jsonPath)
			expected := readFile(t, expectedPath)

			actual, err := CanonicalizeJSON(input)
			if err != nil {
				t.Fatalf("canonicalize %s: %v", jsonPath, err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("canonical bytes mismatch for %s", jsonPath)
			}
		})
	}
}

func TestCanonicalizeJSON_STHVector(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	jsonPath := filepath.Join(vectorsDir, "sth.json")
	expectedPath := filepath.Join(vectorsDir, "sth.jcs")

	input := readFile(t, jsonPath)
	expected := readFile(t, expectedPath)

	actual, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", jsonPath, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("canonical bytes mismatch for %s", jsonPath)
	}
}

func TestCanonicalizeJSON_LeafVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	leafFiles, err := filepath.Glob(filepath.Join(vectorsDir, "leaf_*.json"))
	if err != nil {
		t.Fatalf("glob leaf vectors: %v", err)
	}
	if len(leafFiles) == 0 {
		t.Fatal("no leaf vectors found")
	}
	sort.Strings(leafFiles)

	for _, jsonPath := range leafFiles {
		jsonPath := jsonPath
		t.Run(filepath.Base(jsonPath), func(t *testing.T) {
			expectedHashPath := strings.TrimSuffix(jsonPath, ".json") + ".sha256.hex"
			input := readFile(t, jsonPath)
			expectedHex := strings.TrimSpace(string(readFile(t, expectedHashPath)))

			actual, err := CanonicalizeJSON(input)
			if err != nil {
				t.Fatalf("canonicalize %s: %v", jsonPath, err)
			}
			sum := sha256.Sum256(actual)
			actualHex := hex.EncodeToString(sum[:])
			if actualHex != expectedHex {
				t.Fatalf("leaf hash mismatch for %s", jsonPath)
			}
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
