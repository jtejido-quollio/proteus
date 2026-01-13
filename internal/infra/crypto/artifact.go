package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

func CanonicalizeAndHashArtifact(mediaType string, input []byte) (alg string, hexDigest string, err error) {
	canonical, err := CanonicalizeArtifact(mediaType, input)
	if err != nil {
		return "", "", err
	}
	return "sha256", sha256Hex(canonical), nil
}

func CanonicalizeArtifact(mediaType string, input []byte) ([]byte, error) {
	baseType := normalizeMediaType(mediaType)
	if baseType == "" {
		return nil, errors.New("invalid media type")
	}

	switch baseType {
	case "text/plain":
		return canonicalizeText(input)
	case "application/json":
		return CanonicalizeJSON(input)
	default:
		return nil, fmt.Errorf("unsupported media type: %s", baseType)
	}
}

func sha256Bytes(input []byte) []byte {
	sum := sha256.Sum256(input)
	return sum[:]
}

func sha256Hex(input []byte) string {
	return hex.EncodeToString(sha256Bytes(input))
}

func canonicalizeText(input []byte) ([]byte, error) {
	if !utf8.Valid(input) {
		return nil, errors.New("invalid UTF-8")
	}
	return bytes.ReplaceAll(input, []byte("\r\n"), []byte("\n")), nil
}

func normalizeMediaType(mediaType string) string {
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "" {
		return ""
	}
	parts := strings.SplitN(mediaType, ";", 2)
	return strings.ToLower(strings.TrimSpace(parts[0]))
}
