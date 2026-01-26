package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"proteus/internal/domain"
	cryptoinfra "proteus/internal/infra/crypto"
	"proteus/pkg/capture"
)

type proofDoc struct {
	STH            sthDoc       `json:"sth"`
	InclusionProof inclusionDoc `json:"inclusion_proof"`
}

type sthDoc struct {
	TenantID  string `json:"tenant_id,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type inclusionDoc struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	LeafIndex   int64    `json:"leaf_index"`
	Path        []string `json:"path"`
	STHTreeSize int64    `json:"sth_tree_size"`
	STHRootHash string   `json:"sth_root_hash"`
}

type verifyOutput struct {
	SignatureValid    bool          `json:"signature_valid"`
	ArtifactHashValid *bool         `json:"artifact_hash_valid,omitempty"`
	LogIncluded       bool          `json:"log_included"`
	SubjectHash       domain.Hash   `json:"subject_hash"`
	ManifestID        string        `json:"manifest_id"`
	TenantID          string        `json:"tenant_id"`
	STH               *sthDoc       `json:"sth,omitempty"`
	InclusionProof    *inclusionDoc `json:"inclusion_proof,omitempty"`
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var inPath string
	var artifactPath string
	var mediaType string
	var proofPath string
	var pubHex string
	var pubBase64 string
	var logPubHex string
	var logPubBase64 string
	var requireProof bool

	fs.StringVar(&inPath, "in", "", "envelope JSON path")
	fs.StringVar(&artifactPath, "artifact", "", "artifact path")
	fs.StringVar(&mediaType, "media-type", "", "artifact media type")
	fs.StringVar(&proofPath, "proof", "", "receipt/proof JSON path")
	fs.StringVar(&pubHex, "pubkey-hex", "", "ed25519 public key hex")
	fs.StringVar(&pubBase64, "pubkey-base64", "", "ed25519 public key base64")
	fs.StringVar(&logPubHex, "log-pubkey-hex", "", "ed25519 log public key hex")
	fs.StringVar(&logPubBase64, "log-pubkey-base64", "", "ed25519 log public key base64")
	fs.BoolVar(&requireProof, "require-proof", false, "require proof bundle")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if inPath == "" {
		fmt.Fprintln(os.Stderr, "verify requires --in")
		return 1
	}
	if (pubHex == "" && pubBase64 == "") || (pubHex != "" && pubBase64 != "") {
		fmt.Fprintln(os.Stderr, "verify requires exactly one of --pubkey-hex or --pubkey-base64")
		return 1
	}

	envelopeBytes, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read envelope: %v\n", err)
		return 1
	}
	var envelope domain.SignedManifestEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		fmt.Fprintf(os.Stderr, "decode envelope: %v\n", err)
		return 1
	}

	pubKey, err := parsePublicKey(pubHex, pubBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse public key: %v\n", err)
		return 1
	}

	var artifact []byte
	if artifactPath != "" {
		artifact, err = os.ReadFile(artifactPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read artifact: %v\n", err)
			return 1
		}
	}

	var proof *capture.Proof
	var proofDocOut *proofDoc
	if proofPath != "" {
		payload, err := os.ReadFile(proofPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read proof: %v\n", err)
			return 1
		}
		parsed, err := parseProofBundle(payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode proof: %v\n", err)
			return 1
		}
		proof = parsed.Proof
		proofDocOut = parsed.Doc
	}

	var logPubKey ed25519.PublicKey
	if proof != nil {
		if (logPubHex == "" && logPubBase64 == "") || (logPubHex != "" && logPubBase64 != "") {
			fmt.Fprintln(os.Stderr, "verify requires exactly one of --log-pubkey-hex or --log-pubkey-base64 when --proof is set")
			return 1
		}
		logPubKey, err = parsePublicKey(logPubHex, logPubBase64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse log public key: %v\n", err)
			return 1
		}
	}

	result, err := capture.VerifyEnvelope(envelope, capture.VerifyOptions{
		PublicKey:         pubKey,
		LogPublicKey:      logPubKey,
		Artifact:          artifact,
		ArtifactMediaType: mediaType,
		Proof:             proof,
		RequireProof:      requireProof,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify envelope: %v\n", err)
		return 1
	}

	output := verifyOutput{
		SignatureValid:    result.SignatureValid,
		ArtifactHashValid: result.ArtifactHashValid,
		LogIncluded:       result.LogIncluded,
		SubjectHash:       result.SubjectHash,
		ManifestID:        result.ManifestID,
		TenantID:          result.TenantID,
	}
	if proofDocOut != nil && result.LogIncluded {
		output.STH = &proofDocOut.STH
		output.InclusionProof = &proofDocOut.InclusionProof
	}

	out, err := cryptoinfra.CanonicalizeAny(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		return 1
	}
	if err := writeOutput("", out); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}
	return 0
}

type parsedProof struct {
	Proof *capture.Proof
	Doc   *proofDoc
}

func parseProofBundle(payload []byte) (parsedProof, error) {
	var doc proofDoc
	if err := json.Unmarshal(payload, &doc); err != nil {
		return parsedProof{}, err
	}
	if doc.STH.TreeSize == 0 || doc.STH.RootHash == "" || doc.STH.IssuedAt == "" || doc.STH.Signature == "" {
		return parsedProof{}, errors.New("proof missing sth fields")
	}
	if doc.InclusionProof.STHTreeSize == 0 || doc.InclusionProof.STHRootHash == "" {
		return parsedProof{}, errors.New("proof missing inclusion fields")
	}
	rootHash, err := hex.DecodeString(doc.STH.RootHash)
	if err != nil {
		return parsedProof{}, err
	}
	issuedAt, err := time.Parse(time.RFC3339, doc.STH.IssuedAt)
	if err != nil {
		return parsedProof{}, err
	}
	path := make([][]byte, 0, len(doc.InclusionProof.Path))
	for _, node := range doc.InclusionProof.Path {
		decoded, err := hex.DecodeString(node)
		if err != nil {
			return parsedProof{}, err
		}
		path = append(path, decoded)
	}
	sthRoot, err := hex.DecodeString(doc.InclusionProof.STHRootHash)
	if err != nil {
		return parsedProof{}, err
	}
	proof := &capture.Proof{
		STH: domain.STH{
			TenantID:  doc.STH.TenantID,
			TreeSize:  doc.STH.TreeSize,
			RootHash:  rootHash,
			IssuedAt:  issuedAt,
			Signature: nil,
		},
		STHSignature: doc.STH.Signature,
		Inclusion: domain.InclusionProof{
			TenantID:    doc.InclusionProof.TenantID,
			LeafIndex:   doc.InclusionProof.LeafIndex,
			Path:        path,
			STHTreeSize: doc.InclusionProof.STHTreeSize,
			STHRootHash: sthRoot,
		},
	}
	return parsedProof{Proof: proof, Doc: &doc}, nil
}

func parsePublicKey(hexValue string, b64Value string) (ed25519.PublicKey, error) {
	if hexValue != "" {
		return capture.ParseEd25519PublicKeyHex(hexValue)
	}
	if b64Value != "" {
		return capture.ParseEd25519PublicKeyBase64(b64Value)
	}
	return nil, errors.New("public key is required")
}
