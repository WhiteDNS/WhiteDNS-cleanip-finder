package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PathConfig holds data directory paths
type PathConfig struct {
	DataDir    string
	RoutesFile string
	BannedFile string
	RulesFile  string
	ConfigFile string
}

var (
	pathMu sync.RWMutex
	paths  *PathConfig
)

// InitPaths initializes the storage paths
func InitPaths(dataDir string) error {
	pathMu.Lock()
	defer pathMu.Unlock()

	if dataDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			dataDir = "."
		} else {
			dataDir = filepath.Join(homeDir, ".whitedns")
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	paths = &PathConfig{
		DataDir:    dataDir,
		RoutesFile: filepath.Join(dataDir, "white_routes.txt"),
		BannedFile: filepath.Join(dataDir, "banned_routes.txt"),
		RulesFile:  filepath.Join(dataDir, "routing_rules.json"),
		ConfigFile: filepath.Join(dataDir, "config.json"),
	}

	return nil
}

// GetPaths returns the current path configuration
func GetPaths() *PathConfig {
	pathMu.RLock()
	defer pathMu.RUnlock()

	if paths == nil {
		InitPaths("")
	}
	return paths
}

// ReadTextLines reads a file and returns lines
func ReadTextLines(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// AppendLine appends a line to a file
func AppendLine(filePath string, line string) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line + "\n")
	return err
}

// AtomicWriteText writes text to a file atomically using temp file + rename
func AtomicWriteText(filePath, content string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp_*")
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		os.Remove(tmpFile.Name())
		return err
	}

	tmpFile.Sync()
	return os.Rename(tmpFile.Name(), filePath)
}

// AtomicWriteJSON writes JSON to a file atomically
func AtomicWriteJSON(filePath string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteText(filePath, string(jsonData))
}

// ReadJSON reads a JSON file
func ReadJSON(filePath string, dest interface{}) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, dest)
}

// FileExists checks if a file exists
func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}
