package policyopa

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundleHashIgnoresNonNormativeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`package proteus.policy`), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	hashA, err := ComputeBundleHashFromPath(dir)
	if err != nil {
		t.Fatalf("hash A: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write .DS_Store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "swap.swp"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write swap.swp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego~"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write policy.rego~: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write notes: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "__MACOSX"), 0o755); err != nil {
		t.Fatalf("mkdir __MACOSX: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "__MACOSX", "junk.rego"), []byte("junk"), 0o644); err != nil {
		t.Fatalf("write __MACOSX junk: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "vendored.rego"), []byte("junk"), 0o644); err != nil {
		t.Fatalf("write vendor junk: %v", err)
	}

	hashB, err := ComputeBundleHashFromPath(dir)
	if err != nil {
		t.Fatalf("hash B: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("expected hash to ignore non-normative files")
	}
}

func TestBundleHashChangesOnPolicyChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(path, []byte(`package proteus.policy`), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	hashA, err := ComputeBundleHashFromPath(dir)
	if err != nil {
		t.Fatalf("hash A: %v", err)
	}
	if err := os.WriteFile(path, []byte(`package proteus.policy
default allow = true`), 0o644); err != nil {
		t.Fatalf("rewrite rego: %v", err)
	}
	hashB, err := ComputeBundleHashFromPath(dir)
	if err != nil {
		t.Fatalf("hash B: %v", err)
	}
	if hashA == hashB {
		t.Fatalf("expected hash to change after policy update")
	}
}

func TestBundleHashStableAcrossFileOrder(t *testing.T) {
	dirA := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, "a.rego"), []byte(`package a`), 0o644); err != nil {
		t.Fatalf("write a.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "b.rego"), []byte(`package b`), 0o644); err != nil {
		t.Fatalf("write b.rego: %v", err)
	}
	hashA, err := ComputeBundleHashFromPath(dirA)
	if err != nil {
		t.Fatalf("hash A: %v", err)
	}

	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirB, "b.rego"), []byte(`package b`), 0o644); err != nil {
		t.Fatalf("write b.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirB, "a.rego"), []byte(`package a`), 0o644); err != nil {
		t.Fatalf("write a.rego: %v", err)
	}
	hashB, err := ComputeBundleHashFromPath(dirB)
	if err != nil {
		t.Fatalf("hash B: %v", err)
	}

	if hashA != hashB {
		t.Fatalf("expected hash to be stable across file ordering")
	}
}
