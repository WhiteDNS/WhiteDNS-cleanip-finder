// Package asnexport expands ASN target lists (IPs/CIDRs) into a flat IP list on
// disk. It is deliberately free of any UI dependency so both the terminal UI and
// the mobile bridge can reuse it.
package asnexport

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultExportPath builds a timestamped output path under dataDir/asn_exports.
func DefaultExportPath(dataDir string) string {
	if dataDir == "" {
		dataDir = "."
	}
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dataDir, "asn_exports", fmt.Sprintf("asn_ips-%s.txt", stamp))
}

// ExportTargetsToTXT expands every IP/CIDR target and writes one IP per line to
// outputPath (or a default path when empty). Returns the resolved path and the
// number of IPs written.
func ExportTargetsToTXT(dataDir string, targets []string, outputPath string) (string, int, error) {
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("no ASN targets selected")
	}

	path := strings.TrimSpace(outputPath)
	if path == "" {
		path = DefaultExportPath(dataDir)
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

	// The scanner intentionally caps per-CIDR expansion at 65,536 IPs; the
	// exporter expands without that cap to produce a full list.
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

// expandCIDRNoCap returns every IP in the provided network with no cap.
func expandCIDRNoCap(ipnet *net.IPNet) []string {
	var out []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		out = append(out, ip.String())
	}
	return out
}
