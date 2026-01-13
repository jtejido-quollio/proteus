package main

import (
	"fmt"
	"os"
)

func writeOutput(path string, payload []byte) error {
	if path == "" {
		if _, err := os.Stdout.Write(payload); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout)
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}
