package ui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"whitedns-go/internal/storage"
)

func loadDesyncPairs(dataDir string) map[string][]string {
	path := filepath.Join(dataDir, "desync_pairs.json")
	pairs := make(map[string][]string)
	if err := storage.ReadJSON(path, &pairs); err != nil {
		return map[string][]string{}
	}
	cleaned := make(map[string][]string, len(pairs))
	for sni, ips := range pairs {
		sni = strings.TrimSpace(sni)
		if sni == "" {
			continue
		}
		seen := make(map[string]struct{})
		list := make([]string, 0, len(ips))
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			list = append(list, ip)
		}
		if len(list) > 0 {
			cleaned[sni] = list
		}
	}
	return cleaned
}

func chooseDPIFromPairs(app *App, pairs map[string][]string, state dpiState) (string, string) {
	keys := sortedDPIMapKeys(pairs)
	if len(keys) == 0 {
		return state.DpiSNI, state.DpiIP
	}

	fmt.Println("  [0] Enter SNI and IP manually")
	topLimit := min(10, len(keys))
	for i, key := range keys[:topLimit] {
		fmt.Printf("  [%d] %s (%d IPs)\n", i+1, key, len(pairs[key]))
	}

	choice := strings.TrimSpace(app.readLineInput())
	if choice == "" || choice == "0" {
		return promptManualDPISelection(app, state)
	}
	index, err := strconv.Atoi(choice)
	if err != nil || index < 1 || index > topLimit {
		return promptManualDPISelection(app, state)
	}

	selectedSNI := keys[index-1]
	availableIPs := pairs[selectedSNI]
	previewLimit := min(15, len(availableIPs))
	for i, ip := range availableIPs[:previewLimit] {
		fmt.Printf("    [%d] %s\n", i+1, ip)
	}
	if len(availableIPs) > previewLimit {
		fmt.Printf("    ... and %d more.\n", len(availableIPs)-previewLimit)
	}

	fmt.Printf("\n[?] Select IP [1-%d], or type custom IP (Default 1): ", previewLimit)
	ipChoice := strings.TrimSpace(app.readLineInput())
	selectedIP := availableIPs[0]
	if i, err := strconv.Atoi(ipChoice); err == nil && i >= 1 && i <= len(availableIPs) {
		selectedIP = availableIPs[i-1]
	} else if ipChoice != "" && !strings.Contains(ipChoice, " ") {
		selectedIP = ipChoice
	}
	return selectedSNI, selectedIP
}

func promptManualDPISelection(app *App, state dpiState) (string, string) {
	fmt.Printf("[?] Enter target SNI or domain [default %s]: ", state.DpiSNI)
	sni := strings.TrimSpace(app.readLineInput())
	if sni == "" {
		sni = state.DpiSNI
	}
	fmt.Printf("[?] Enter clean IP [current %s, blank to keep]: ", state.DpiIP)
	ip := strings.TrimSpace(app.readLineInput())
	if ip == "" {
		ip = state.DpiIP
	}
	return sni, ip
}

func parseStrategyList(raw string) []string {
	valid := map[string]struct{}{"oob": {}, "bad_csum": {}, "ttl": {}, "syn": {}, "rst": {}, "fin": {}, "classic": {}}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	seen := make(map[string]struct{})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if _, ok := valid[part]; !ok {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	if len(out) == 0 {
		return []string{"oob"}
	}
	sort.Strings(out)
	return out
}
