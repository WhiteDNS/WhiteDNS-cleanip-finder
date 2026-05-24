package tlsprobe

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultDomains returns the built-in list of hostnames used for TLS hostname
// probing. Users may add their own domains which will be merged with this set.
func DefaultDomains() []string {
	return []string{
		"sourceforge.net",
		"tandfonline.com",
		"static.cloudflareinsights.com",
		"sciencedirect.com",
		"e7.c.lencr.org",
		"hcaptcha.com",
		"serverless.hcaptcha.com",
		"emails.github.com",
	}
}

// LoadCustom loads user-supplied domains from a file in the data directory.
// The file path is dataDir/tls_probe_domains.txt. If the file cannot be read
// an empty slice is returned.
func LoadCustom(dataDir string) []string {
	if dataDir == "" {
		dataDir = "."
	}
	path := filepath.Join(dataDir, "tls_probe_domains.txt")
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// SaveCustom writes the provided domains to dataDir/tls_probe_domains.txt. It
// overwrites existing content.
func SaveCustom(dataDir string, domains []string) error {
	if dataDir == "" {
		dataDir = "."
	}
	path := filepath.Join(dataDir, "tls_probe_domains.txt")
	// ensure parent directory exists
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	// Normalize and dedupe
	seen := make(map[string]struct{})
	var lines []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		lines = append(lines, d)
	}
	sort.Strings(lines)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// GetDomains returns merged default + custom domains (unique, sorted).
// Duplicate entries across the built-in list and custom file are intentionally
// deduplicated so built-in defaults keep precedence and users cannot force
// repeated probes for the same hostname.
func GetDomains(dataDir string) []string {
	def := DefaultDomains()
	custom := LoadCustom(dataDir)
	seen := make(map[string]struct{})
	var out []string
	for _, d := range def {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	for _, d := range custom {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
