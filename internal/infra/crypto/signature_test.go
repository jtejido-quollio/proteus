package crypto

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"proteus/internal/domain"
)

type keyVector struct {
	Alg             string `json:"alg"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

func TestVerifySignatureVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "..", "testvectors", "v0")
	keyBytes := readFile(t, filepath.Join(vectorsDir, "keys.json"))
	var keys keyVector
	if err := json.Unmarshal(keyBytes, &keys); err != nil {
		t.Fatalf("unmarshal keys.json: %v", err)
	}
	pubKey, err := base64.StdEncoding.DecodeString(keys.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	manifestFiles, err := filepath.Glob(filepath.Join(vectorsDir, "manifest_*.jcs"))
	if err != nil {
		t.Fatalf("glob manifest vectors: %v", err)
	}
	if len(manifestFiles) == 0 {
		t.Fatal("no manifest vectors found")
	}
	sort.Strings(manifestFiles)

	service := &Service{}
	for _, manifestPath := range manifestFiles {
		manifestPath := manifestPath
		t.Run(filepath.Base(manifestPath), func(t *testing.T) {
			manifestBytes := readFile(t, manifestPath)
			index := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(manifestPath), "manifest_"), ".jcs")
			sigPath := filepath.Join(vectorsDir, "signature_"+index+".b64")
			sigValue := strings.TrimSpace(string(readFile(t, sigPath)))
			sig := domain.Signature{Alg: keys.Alg, Value: sigValue}

			if err := service.VerifySignature(manifestBytes, sig, pubKey); err != nil {
				t.Fatalf("verify signature failed: %v", err)
			}

			mutated := append([]byte(nil), manifestBytes...)
			mutated[len(mutated)-1] ^= 0x01
			if err := service.VerifySignature(mutated, sig, pubKey); err == nil {
				t.Fatal("expected verification failure for mutated payload")
			}
		})
	}
}
