package nmap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

var (
	nmapPath string
	nmapOnce sync.Once
)

// Initialize extracts nmap to a temporary location and returns the path
func Initialize() (string, error) {
	var err error
	nmapOnce.Do(func() {
		nmapPath, err = extractNmap()
	})
	return nmapPath, err
}

// extractNmap resolves a usable nmap executable path.
// If a bundled binary is present in the future, it can be extracted here.
func extractNmap() (string, error) {
	if env := os.Getenv("WHITEDNS_NMAP_PATH"); env != "" && fileExists(env) {
		return env, nil
	}
	if path, err := exec.LookPath("nmap.exe"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("nmap"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("nmap executable not found; install nmap or set WHITEDNS_NMAP_PATH")
}

// GetPath returns the path to the nmap executable (initializes if needed)
func GetPath() (string, error) {
	if nmapPath != "" {
		return nmapPath, nil
	}
	return Initialize()
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Cleanup removes the extracted nmap executable (optional)
func Cleanup() error {
	if nmapPath == "" {
		return nil
	}
	if filepath.Dir(nmapPath) == os.TempDir() {
		return os.Remove(nmapPath)
	}
	return nil
}
