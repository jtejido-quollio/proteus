package policyopa

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cryptoinfra "proteus/internal/infra/crypto"
)

type bundleHashPayload struct {
	Files []bundleHashFile `json:"files"`
}

type bundleHashFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func ComputeBundleHashFromPath(bundlePath string) (string, error) {
	return ComputeBundleHashFromFS(os.DirFS(bundlePath), ".")
}

func ComputeBundleHashFromFS(fsys fs.FS, root string) (string, error) {
	files, err := collectBundleFiles(fsys, root)
	if err != nil {
		return "", err
	}
	payload := bundleHashPayload{Files: files}
	canonical, err := cryptoinfra.CanonicalizeAny(payload)
	if err != nil {
		return "", err
	}
	sum := sha256Hex(canonical)
	return sum, nil
}

func collectBundleFiles(fsys fs.FS, root string) ([]bundleHashFile, error) {
	var files []bundleHashFile
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(path) {
				return fs.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path) {
			return nil
		}
		if !isNormativeFile(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		entry := bundleHashFile{
			Path:   filepath.ToSlash(path),
			SHA256: sha256Hex(data),
		}
		files = append(files, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	return files, nil
}

func shouldSkipDir(path string) bool {
	base := filepath.Base(path)
	if base == "__MACOSX" || base == "vendor" {
		return true
	}
	if strings.HasPrefix(base, ".") {
		return true
	}
	return false
}

func shouldSkipFile(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return true
	}
	if strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") {
		return true
	}
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".bundle") || strings.HasSuffix(lower, ".zip") {
		return true
	}
	return false
}

func isNormativeFile(path string) bool {
	base := filepath.Base(path)
	if base == "data.json" || base == "manifest.json" {
		return true
	}
	return strings.HasSuffix(base, ".rego")
}
