package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"proteus/internal/domain"
)

func TestComputeLeafHashVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	leafFiles, err := filepath.Glob(filepath.Join(vectorsDir, "leaf_*.json"))
	if err != nil {
		t.Fatalf("glob leaf vectors: %v", err)
	}
	if len(leafFiles) == 0 {
		t.Fatal("no leaf vectors found")
	}
	sort.Strings(leafFiles)

	service := &Service{}
	for _, jsonPath := range leafFiles {
		jsonPath := jsonPath
		t.Run(filepath.Base(jsonPath), func(t *testing.T) {
			input := readFile(t, jsonPath)
			expectedHex := strings.TrimSpace(string(readFile(t, strings.TrimSuffix(jsonPath, ".json")+".sha256.hex")))

			var env domain.SignedManifestEnvelope
			if err := json.Unmarshal(input, &env); err != nil {
				t.Fatalf("unmarshal %s: %v", jsonPath, err)
			}

			actual, err := service.ComputeLeafHash(env)
			if err != nil {
				t.Fatalf("compute leaf hash: %v", err)
			}

			expected, err := hex.DecodeString(expectedHex)
			if err != nil {
				t.Fatalf("decode expected hex: %v", err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("leaf hash mismatch for %s", jsonPath)
			}
		})
	}
}
