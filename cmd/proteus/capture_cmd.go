package main

import (
	"flag"
	"fmt"
	"os"

	"proteus/pkg/capture"
)

func runCapture(args []string) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var inPath string
	var mediaType string
	var outPath string
	var outCanonical string
	fs.StringVar(&inPath, "in", "", "input artifact path")
	fs.StringVar(&mediaType, "media-type", "", "artifact media type")
	fs.StringVar(&outPath, "out", "", "output JSON path (default stdout)")
	fs.StringVar(&outCanonical, "out-canonical", "", "output canonical bytes path")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if inPath == "" || mediaType == "" {
		fmt.Fprintln(os.Stderr, "capture requires --in and --media-type")
		return 1
	}

	input, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read artifact: %v\n", err)
		return 1
	}

	result, err := capture.CaptureArtifact(mediaType, input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture artifact: %v\n", err)
		return 1
	}

	if outCanonical != "" {
		if err := os.WriteFile(outCanonical, result.Canonical, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write canonical bytes: %v\n", err)
			return 1
		}
	}

	payload, err := capture.MarshalHash(result.Hash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal hash: %v\n", err)
		return 1
	}
	if err := writeOutput(outPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}
	return 0
}
