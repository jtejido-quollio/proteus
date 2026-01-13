package capture

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proteus/internal/domain"
)

type vectorKeys struct {
	KID     string `json:"kid"`
	SeedHex string `json:"seed_hex"`
}

func TestSignManifest_Vector1(t *testing.T) {
	vectorsDir := filepath.Join("..", "..", "testvectors", "v0")
	manifestPath := filepath.Join(vectorsDir, "manifest_1.json")
	keysPath := filepath.Join(vectorsDir, "keys.json")
	sigPath := filepath.Join(vectorsDir, "signature_1.b64")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest domain.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	keysBytes, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read keys: %v", err)
	}
	var keys vectorKeys
	if err := json.Unmarshal(keysBytes, &keys); err != nil {
		t.Fatalf("decode keys: %v", err)
	}
	seed, err := hex.DecodeString(keys.SeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	built, err := BuildManifest(ManifestInput{
		Schema:     manifest.Schema,
		ManifestID: manifest.ManifestID,
		TenantID:   manifest.TenantID,
		Subject:    manifest.Subject,
		Actor:      manifest.Actor,
		Tool:       manifest.Tool,
		Time:       manifest.Time,
		Inputs:     manifest.Inputs,
		Claims:     manifest.Claims,
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	signature, _, err := SignManifest(built, keys.KID, privateKey)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}

	wantBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	want := strings.TrimSpace(string(wantBytes))
	if signature.Value != want {
		t.Fatalf("signature mismatch: got %s want %s", signature.Value, want)
	}
}
