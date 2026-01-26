package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"proteus/internal/domain"
	"proteus/internal/infra/merkle"
)

type sthVector struct {
	IssuedAt string `json:"issued_at"`
	RootHash string `json:"root_hash"`
	TenantID string `json:"tenant_id"`
	TreeSize int64  `json:"tree_size"`
}

func TestSTHCanonicalizationAndSignature(t *testing.T) {
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

	sthBytes := readFile(t, filepath.Join(vectorsDir, "sth.json"))
	var vec sthVector
	if err := json.Unmarshal(sthBytes, &vec); err != nil {
		t.Fatalf("unmarshal sth.json: %v", err)
	}
	rootHash, err := hex.DecodeString(vec.RootHash)
	if err != nil {
		t.Fatalf("decode root hash: %v", err)
	}
	issuedAt, err := time.Parse(time.RFC3339, vec.IssuedAt)
	if err != nil {
		t.Fatalf("parse issued_at: %v", err)
	}
	leaves := loadLeafHashes(t, vectorsDir)
	if vec.TreeSize <= 0 || vec.TreeSize > int64(len(leaves)) {
		t.Fatalf("invalid tree size in vectors: %d", vec.TreeSize)
	}
	computedRoot, err := merkle.Root(leaves[:int(vec.TreeSize)])
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	if !bytes.Equal(computedRoot, rootHash) {
		t.Fatal("computed root hash mismatch for sth")
	}
	sth := domain.TreeHead{
		TenantID: vec.TenantID,
		TreeSize: vec.TreeSize,
		RootHash: rootHash,
		IssuedAt: issuedAt,
	}

	service := &Service{}
	canonical, err := service.CanonicalizeSTH(sth)
	if err != nil {
		t.Fatalf("canonicalize sth: %v", err)
	}

	expected := readFile(t, filepath.Join(vectorsDir, "sth.jcs"))
	if !bytes.Equal(canonical, expected) {
		t.Fatal("canonical bytes mismatch for sth")
	}

	sigValue := string(bytes.TrimSpace(readFile(t, filepath.Join(vectorsDir, "sth.signature.b64"))))
	if err := service.VerifySignature(expected, domain.Signature{Alg: keys.Alg, Value: sigValue}, pubKey); err != nil {
		t.Fatalf("verify sth signature over sth.jcs: %v", err)
	}
	if err := service.VerifySTHSignature(sth, sigValue, pubKey); err != nil {
		t.Fatalf("verify sth signature: %v", err)
	}

	mutated := append([]byte(nil), canonical...)
	mutated[len(mutated)-1] ^= 0x01
	if err := service.VerifySignature(mutated, domain.Signature{Alg: keys.Alg, Value: sigValue}, pubKey); err == nil {
		t.Fatal("expected verification failure for mutated sth payload")
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
		hash, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("decode leaf hash: %v", err)
		}
		leaves = append(leaves, hash)
	}
	return leaves
}
