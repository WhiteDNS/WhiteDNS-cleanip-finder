package bundledata

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed embedded/IranASNs/filtered_ipv4.csv embedded/IranASNs/filtered_ipv6.csv embedded/assets/cf-domains.txt
var bundledFS embed.FS

const (
	embeddedASNv4Path   = "embedded/IranASNs/filtered_ipv4.csv"
	embeddedASNv6Path   = "embedded/IranASNs/filtered_ipv6.csv"
	embeddedSNIListPath = "embedded/assets/cf-domains.txt"
	configMakerFolder   = "config maker"
)

func ASNIPv4CSV() ([]byte, error) {
	return bundledFS.ReadFile(embeddedASNv4Path)
}

func ASNIPv4CSVReader() (io.ReadCloser, error) {
	return bundledFS.Open(embeddedASNv4Path)
}

func ASNIPv6CSV() ([]byte, error) {
	return bundledFS.ReadFile(embeddedASNv6Path)
}

func ASNIPv6CSVReader() (io.ReadCloser, error) {
	return bundledFS.Open(embeddedASNv6Path)
}

func LoadSNIPatterns() ([]string, error) {
	data, err := bundledFS.ReadFile(embeddedSNIListPath)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 256)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out, nil
}

func EnsureConfigMakerDataDir(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", fmt.Errorf("empty dataDir")
	}

	supportDir := filepath.Join(dataDir, configMakerFolder)
	if err := os.MkdirAll(supportDir, 0o755); err != nil {
		return "", err
	}

	return supportDir, nil
}

func EnsureRuntimeData(dataDir string) error {
	_, err := EnsureConfigMakerDataDir(dataDir)
	return err
}
