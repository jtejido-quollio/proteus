package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func run(args []string) int {
	if len(args) < 2 {
		usage(args)
		return 1
	}

	switch args[1] {
	case "bundle":
		if len(args) >= 3 && args[2] == "verify" {
			return runBundleVerify(args[3:])
		}
	case "capture":
		return runCapture(args[2:])
	case "manifest":
		if len(args) >= 3 {
			switch args[2] {
			case "build":
				return runManifestBuild(args[3:])
			case "sign":
				return runManifestSign(args[3:])
			}
		}
	case "verify":
		return runVerify(args[2:])
	}

	usage(args)
	return 1
}

func usage(args []string) {
	name := "proteus"
	if len(args) > 0 && args[0] != "" {
		name = filepath.Base(args[0])
	}
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  %s capture --media-type <type> --in <file> [--out <file>] [--out-canonical <file>]\n", name)
	fmt.Fprintf(os.Stderr, "  %s manifest build --manifest-id <id> --tenant-id <id> --subject-hash <hex> --subject-media-type <type> --subject-type <type> --actor-id <id> --actor-type <type> --tool-name <name> --tool-version <version> --created-at <rfc3339> --submitted-at <rfc3339> [--out <file>] [--inputs <file>] [--claims <file>]\n", name)
	fmt.Fprintf(os.Stderr, "  %s manifest sign --in <manifest.json> --kid <kid> (--key-hex <hex>|--key-base64 <b64>) [--out <file>] [--cert-chain <file>]\n", name)
	fmt.Fprintf(os.Stderr, "  %s verify --in <envelope.json> (--pubkey-hex <hex>|--pubkey-base64 <b64>) [--artifact <file>] [--media-type <type>] [--proof <receipt.json>] [--log-pubkey-hex <hex>|--log-pubkey-base64 <b64>] [--require-proof]\n", name)
	fmt.Fprintf(os.Stderr, "  %s bundle verify <evidence_bundle.json>\n", name)
}
