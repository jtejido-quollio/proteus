package crypto

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"proteus/internal/domain"
)

func TestCanonicalizeManifestVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	manifestFiles, err := filepath.Glob(filepath.Join(vectorsDir, "manifest_*.json"))
	if err != nil {
		t.Fatalf("glob manifest vectors: %v", err)
	}
	if len(manifestFiles) == 0 {
		t.Fatal("no manifest vectors found")
	}
	sort.Strings(manifestFiles)

	service := &Service{}
	for _, jsonPath := range manifestFiles {
		t.Run(filepath.Base(jsonPath), func(t *testing.T) {
			expectedPath := strings.TrimSuffix(jsonPath, ".json") + ".jcs"
			input := readFile(t, jsonPath)
			expected := readFile(t, expectedPath)

			var manifest domain.Manifest
			if err := json.Unmarshal(input, &manifest); err != nil {
				t.Fatalf("unmarshal %s: %v", jsonPath, err)
			}

			actual, err := service.CanonicalizeManifest(manifest)
			if err != nil {
				t.Fatalf("canonicalize %s: %v", jsonPath, err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("canonical bytes mismatch for %s", jsonPath)
			}
		})
	}
}
