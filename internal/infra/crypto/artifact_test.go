package crypto

import "testing"

func TestCanonicalizeAndHashArtifact_TextCRLF(t *testing.T) {
	input := []byte("line1\r\nline2\r\n")
	alg, hexDigest, err := CanonicalizeAndHashArtifact("text/plain", input)
	if err != nil {
		t.Fatalf("canonicalize text: %v", err)
	}
	if alg != "sha256" {
		t.Fatalf("expected sha256 alg, got %q", alg)
	}
	const expectedHex = "2751a3a2f303ad21752038085e2b8c5f98ecff61a2e4ebbd43506a941725be80"
	if hexDigest != expectedHex {
		t.Fatalf("unexpected hash: %s", hexDigest)
	}
}

func TestCanonicalizeAndHashArtifact_TextInvalidUTF8(t *testing.T) {
	_, _, err := CanonicalizeAndHashArtifact("text/plain", []byte{0xff})
	if err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
}

func TestCanonicalizeAndHashArtifact_JSON(t *testing.T) {
	input := []byte("{\"b\":1, \"a\":2}")
	alg, hexDigest, err := CanonicalizeAndHashArtifact("application/json", input)
	if err != nil {
		t.Fatalf("canonicalize json: %v", err)
	}
	if alg != "sha256" {
		t.Fatalf("expected sha256 alg, got %q", alg)
	}
	const expectedHex = "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772"
	if hexDigest != expectedHex {
		t.Fatalf("unexpected hash: %s", hexDigest)
	}
}

func TestCanonicalizeAndHashArtifact_UnsupportedMediaType(t *testing.T) {
	_, _, err := CanonicalizeAndHashArtifact("application/xml", []byte("<a/>"))
	if err == nil {
		t.Fatal("expected error for unsupported media type")
	}
}
