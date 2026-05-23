package bridge

import (
	"fmt"
	"os"
	"whitedns-go/internal/nmap"
)

// InitializeNmap initializes the bundled nmap and returns its path
// This can be called from Python via exec or other bridging mechanisms
func InitializeNmap() (string, error) {
	path, err := nmap.Initialize()
	if err != nil {
		return "", fmt.Errorf("failed to initialize nmap: %w", err)
	}

	// Set environment variable so Python can find it
	if err := os.Setenv("WHITEDNS_NMAP_PATH", path); err != nil {
		return "", fmt.Errorf("failed to set nmap environment: %w", err)
	}

	return path, nil
}

// GetNmapPath returns the path to nmap executable
func GetNmapPath() (string, error) {
	return nmap.GetPath()
}
