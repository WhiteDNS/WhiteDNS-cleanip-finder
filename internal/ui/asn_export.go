package ui

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitedns-go/internal/asn"
)

func defaultASNExportPath(dataDir string) string {
	if dataDir == "" {
		dataDir = "."
	}
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dataDir, "asn_exports", fmt.Sprintf("asn_ips-%s.txt", stamp))
}

func exportASNTargetsToTXT(dataDir string, targets []string, outputPath string) (string, int, error) {
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("no ASN targets selected")
	}

	path := strings.TrimSpace(outputPath)
	if path == "" {
		path = defaultASNExportPath(dataDir)
	} else if !filepath.IsAbs(path) {
		if dataDir == "" {
			dataDir = "."
		}
		path = filepath.Join(dataDir, path)
	}
	path = filepath.Clean(path)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}

	f, err := os.Create(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	written := 0

	if _, err := fmt.Fprintln(w, "# ASN IP export"); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w, "# Generated:", time.Now().Format(time.RFC3339)); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w, "# Source ASNs:", len(targets)); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return "", 0, err
	}

	for _, target := range targets {
		count, err := writeExpandedTargetNoCap(w, target)
		if err != nil {
			return "", 0, err
		}
		written += count
	}

	if err := w.Flush(); err != nil {
		return "", 0, err
	}

	return path, written, nil
}

func writeExpandedTargetNoCap(w *bufio.Writer, target string) (int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, nil
	}

	if ip := net.ParseIP(target); ip != nil && !strings.Contains(target, "/") {
		if _, err := fmt.Fprintln(w, target); err != nil {
			return 0, err
		}
		return 1, nil
	}

	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		if ip := net.ParseIP(target); ip != nil {
			if _, err := fmt.Fprintln(w, ip.String()); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, err
	}

	// Use the uncapped expansion helper so exporter logic is explicitly
	// separated from the scanner's capped expansion logic. The scanner
	// intentionally limits per-CIDR expansion to 65,536 IPs; this exporter
	// must expand without that cap to produce a full list for export.
	ips := expandCIDRNoCap(ipnet)
	for _, ip := range ips {
		if _, err := fmt.Fprintln(w, ip); err != nil {
			return 0, err
		}
	}
	return len(ips), nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// expandCIDRNoCap returns every IP in the provided network without applying
// any artificial caps. This is intentionally separate from the scanner's
// `expandCIDR` which takes a maxIPs parameter and is used by the scanner
// pipeline to avoid excessive memory usage and unintended large scans.
func expandCIDRNoCap(ipnet *net.IPNet) []string {
	var out []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		out = append(out, ip.String())
	}
	return out
}

func exportASNGroupsToTXT(dataDir string, groups []asn.ASNGroup, outputPath string) (string, int, error) {
	cidrs := make([]string, 0)
	for _, group := range groups {
		cidrs = append(cidrs, group.CIDRs...)
	}
	return exportASNTargetsToTXT(dataDir, cidrs, outputPath)
}
