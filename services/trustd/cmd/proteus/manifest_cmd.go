package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"proteus/internal/domain"
	"proteus/pkg/capture"
)

func runManifestBuild(args []string) int {
	fs := flag.NewFlagSet("manifest build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var schema string
	var manifestID string
	var tenantID string
	var subjectType string
	var subjectMediaType string
	var subjectHash string
	var subjectHashAlg string
	var subjectSize int64
	var subjectURI string
	var actorID string
	var actorType string
	var actorDisplay string
	var toolName string
	var toolVersion string
	var toolVendor string
	var toolEnv string
	var createdAt string
	var submittedAt string
	var inputsPath string
	var claimsPath string
	var outPath string

	fs.StringVar(&schema, "schema", capture.DefaultManifestSchema, "manifest schema")
	fs.StringVar(&manifestID, "manifest-id", "", "manifest id")
	fs.StringVar(&tenantID, "tenant-id", "", "tenant id")
	fs.StringVar(&subjectType, "subject-type", "", "subject type")
	fs.StringVar(&subjectMediaType, "subject-media-type", "", "subject media type")
	fs.StringVar(&subjectHash, "subject-hash", "", "subject hash hex")
	fs.StringVar(&subjectHashAlg, "subject-hash-alg", "sha256", "subject hash algorithm")
	fs.Int64Var(&subjectSize, "subject-size-bytes", 0, "subject size bytes")
	fs.StringVar(&subjectURI, "subject-uri", "", "subject uri")
	fs.StringVar(&actorID, "actor-id", "", "actor id")
	fs.StringVar(&actorType, "actor-type", "", "actor type")
	fs.StringVar(&actorDisplay, "actor-display", "", "actor display")
	fs.StringVar(&toolName, "tool-name", "", "tool name")
	fs.StringVar(&toolVersion, "tool-version", "", "tool version")
	fs.StringVar(&toolVendor, "tool-vendor", "", "tool vendor")
	fs.StringVar(&toolEnv, "tool-environment", "", "tool environment")
	fs.StringVar(&createdAt, "created-at", "", "created_at (RFC3339)")
	fs.StringVar(&submittedAt, "submitted-at", "", "submitted_at (RFC3339)")
	fs.StringVar(&inputsPath, "inputs", "", "inputs JSON file (array)")
	fs.StringVar(&claimsPath, "claims", "", "claims JSON file (object)")
	fs.StringVar(&outPath, "out", "", "output manifest path (default stdout)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if manifestID == "" || tenantID == "" || subjectHash == "" || subjectMediaType == "" || subjectType == "" || actorID == "" || actorType == "" || toolName == "" || toolVersion == "" || createdAt == "" || submittedAt == "" {
		fmt.Fprintln(os.Stderr, "manifest build requires manifest, subject, actor, tool, and time fields")
		return 1
	}

	created, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse created-at: %v\n", err)
		return 1
	}
	submitted, err := time.Parse(time.RFC3339, submittedAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse submitted-at: %v\n", err)
		return 1
	}

	inputs := []domain.InputArtifact{}
	if inputsPath != "" {
		inputsBytes, err := os.ReadFile(inputsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read inputs: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(inputsBytes, &inputs); err != nil {
			fmt.Fprintf(os.Stderr, "decode inputs: %v\n", err)
			return 1
		}
	}

	var claims map[string]any
	if claimsPath != "" {
		claimsBytes, err := os.ReadFile(claimsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read claims: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(claimsBytes, &claims); err != nil {
			fmt.Fprintf(os.Stderr, "decode claims: %v\n", err)
			return 1
		}
	}

	manifest, err := capture.BuildManifest(capture.ManifestInput{
		Schema:     schema,
		ManifestID: manifestID,
		TenantID:   tenantID,
		Subject: domain.Subject{
			Type:      subjectType,
			MediaType: subjectMediaType,
			Hash: domain.Hash{
				Alg:   subjectHashAlg,
				Value: subjectHash,
			},
			SizeBytes: subjectSize,
			URI:       subjectURI,
		},
		Actor: domain.Actor{
			Type:    actorType,
			ID:      actorID,
			Display: actorDisplay,
		},
		Tool: domain.Tool{
			Name:        toolName,
			Version:     toolVersion,
			Vendor:      toolVendor,
			Environment: toolEnv,
		},
		Time: domain.ManifestTime{
			CreatedAt:   created,
			SubmittedAt: submitted,
		},
		Inputs: inputs,
		Claims: claims,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build manifest: %v\n", err)
		return 1
	}

	payload, err := capture.MarshalManifest(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal manifest: %v\n", err)
		return 1
	}
	if err := writeOutput(outPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}
	return 0
}

func runManifestSign(args []string) int {
	fs := flag.NewFlagSet("manifest sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var inPath string
	var outPath string
	var kid string
	var keyHex string
	var keyBase64 string
	var certChainPath string

	fs.StringVar(&inPath, "in", "", "manifest JSON path")
	fs.StringVar(&outPath, "out", "", "output envelope path (default stdout)")
	fs.StringVar(&kid, "kid", "", "key id")
	fs.StringVar(&keyHex, "key-hex", "", "ed25519 private key hex (seed or private key)")
	fs.StringVar(&keyBase64, "key-base64", "", "ed25519 private key base64 (seed or private key)")
	fs.StringVar(&certChainPath, "cert-chain", "", "cert chain JSON file (array)")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if inPath == "" || kid == "" {
		fmt.Fprintln(os.Stderr, "manifest sign requires --in and --kid")
		return 1
	}
	if (keyHex == "" && keyBase64 == "") || (keyHex != "" && keyBase64 != "") {
		fmt.Fprintln(os.Stderr, "manifest sign requires exactly one of --key-hex or --key-base64")
		return 1
	}

	manifestBytes, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read manifest: %v\n", err)
		return 1
	}
	var manifest domain.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "decode manifest: %v\n", err)
		return 1
	}

	var edPrivateKey ed25519.PrivateKey
	var keyErr error
	if keyHex != "" {
		edPrivateKey, keyErr = capture.ParseEd25519PrivateKeyHex(keyHex)
	} else {
		edPrivateKey, keyErr = capture.ParseEd25519PrivateKeyBase64(keyBase64)
	}
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "parse private key: %v\n", keyErr)
		return 1
	}

	certChain := []string(nil)
	if certChainPath != "" {
		certBytes, err := os.ReadFile(certChainPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read cert chain: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(certBytes, &certChain); err != nil {
			fmt.Fprintf(os.Stderr, "decode cert chain: %v\n", err)
			return 1
		}
	}

	signature, _, err := capture.SignManifest(manifest, kid, edPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign manifest: %v\n", err)
		return 1
	}
	envelope := capture.BuildEnvelope(manifest, signature, certChain)
	payload, err := capture.MarshalEnvelope(envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal envelope: %v\n", err)
		return 1
	}
	if err := writeOutput(outPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}
	return 0
}
