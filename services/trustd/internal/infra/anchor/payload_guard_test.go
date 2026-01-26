package anchor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvidersDoNotBuildPayload(t *testing.T) {
	dirs := []string{
		"rekor",
		"blockchain",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read provider dir %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if strings.Contains(string(data), "BuildPayload(") {
				t.Fatalf("provider must not call BuildPayload: %s", path)
			}
		}
	}
}
