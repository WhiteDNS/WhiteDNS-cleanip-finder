package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"whitedns-go/internal/dnsscan"
	"whitedns-go/internal/tlsprobe"
)

// screenDNSPorts lets the user pick which DNS transport/ports to probe before a
// resolver scan starts (port 53 Do53, DoT, DoH, or all).
const screenDNSPorts = "dns_ports"

// screenDNSWorkers lets the user pick the resolver worker-pool size (scan
// concurrency) after the transport is chosen and before the scan launches.
const screenDNSWorkers = "dns_workers"

// dnsWorkerPreset couples a menu label with a concurrency (worker count).
type dnsWorkerPreset struct {
	label   string
	workers int
}

var dnsWorkerPresets = []dnsWorkerPreset{
	{"Gentle - 16 workers (slow links / low RAM)", 16},
	{"Low - 32 workers", 32},
	{"Default - 64 workers", 64},
	{"High - 128 workers", 128},
	{"Very High - 256 workers", 256},
	{"Max - 512 workers (fast link, may drop UDP)", 512},
}

// defaultDNSWorkers is used when the user has not visited the worker screen.
const defaultDNSWorkers = 64

// screenDNSNearby asks whether to expand the /24 around each tunnel-ready
// resolver and rescan it ("Test Nearby IPs"). This can multiply the scan size
// by 256 per hit, so it is opt-in rather than automatic.
const screenDNSNearby = "dns_nearby"

// dnsNearbyPreset couples a menu label with the nearby-expansion toggle.
type dnsNearbyPreset struct {
	label  string
	enable bool
}

var dnsNearbyPresets = []dnsNearbyPreset{
	{"No - scan only the resolvers I listed (default)", false},
	{"Yes - also expand the /24 around each tunnel-ready hit", true},
}

// dnsPortPreset couples a menu label with the engine protocol + port set.
type dnsPortPreset struct {
	label    string
	protocol string // dnsscan.Options.Protocol
	ports    []int
}

var dnsPortPresets = []dnsPortPreset{
	{"Port 53 - standard DNS (UDP + TCP)", "both", []int{53}},
	{"DoT - DNS-over-TLS (853)", "all", []int{853}},
	{"DoH - DNS-over-HTTPS (443)", "all", []int{443}},
	{"All valid DNS ports (53 + 853 + 443)", "all", []int{53, 853, 443}},
}

// screenDNSReference lets the user pick the trusted reference resolver used to
// build the truth table that candidate answers are checked against for
// poisoning.
const screenDNSReference = "dns_reference"

// dnsReferencePreset couples a menu label with a dnsscan reference provider id.
type dnsReferencePreset struct {
	label    string
	provider string // dnsscan.ReferenceGoogle / ReferenceCloudflare
}

var dnsReferencePresets = []dnsReferencePreset{
	{"Google Public DNS - 8.8.8.8 (default reference)", dnsscan.ReferenceGoogle},
	{"Cloudflare - 1.1.1.1", dnsscan.ReferenceCloudflare},
	{"Quad9 - 9.9.9.9", dnsscan.ReferenceQuad9},
}

// gotoDNSPorts is entered once resolver targets are chosen (from any source).
func (m *tuiModel) gotoDNSPorts(targets []string) {
	m.scanConfig.Targets = targets
	m.pushScreen(screenDNSPorts)
	m.cursor = 0
}

// handleDNSPortsScreen picks the transport preset and launches the scan.
func (m tuiModel) handleDNSPortsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(dnsPortPresets)-1 {
			m.cursor++
		}
	case "esc":
		m.goBack()
	case "enter":
		p := dnsPortPresets[m.cursor]
		m.dnsProtocol = p.protocol
		m.scanConfig.Ports = append([]int(nil), p.ports...)
		m.addLog(fmt.Sprintf("DNS scan transport: %s", p.label))
		m.pushScreen(screenDNSReference)
		m.cursor = 0 // default to Google
	}
	return m, nil
}

// viewDNSPorts renders the transport picker using the shared list style.
func (m tuiModel) viewDNSPorts(w, h int) string {
	items := make([]string, len(dnsPortPresets))
	for i, p := range dnsPortPresets {
		items[i] = p.label
	}
	return m.viewList(w, h, "DNS PORTS / TRANSPORT", items,
		"↑↓ navigate  ·  Enter next  ·  Esc back")
}

// handleDNSReferenceScreen picks the trusted reference resolver, then advances
// to the worker-count picker.
func (m tuiModel) handleDNSReferenceScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(dnsReferencePresets)-1 {
			m.cursor++
		}
	case "esc":
		m.goBack()
	case "enter":
		p := dnsReferencePresets[m.cursor]
		m.dnsReference = p.provider
		m.addLog(fmt.Sprintf("DNS scan reference resolver: %s", p.label))
		m.pushScreen(screenDNSWorkers)
		m.cursor = 2 // default to the 64-worker preset
	}
	return m, nil
}

// viewDNSReference renders the reference-resolver picker using the list style.
func (m tuiModel) viewDNSReference(w, h int) string {
	items := make([]string, len(dnsReferencePresets))
	for i, p := range dnsReferencePresets {
		items[i] = p.label
	}
	return m.viewList(w, h, "REFERENCE RESOLVER (truth source)", items,
		"↑↓ navigate  ·  Enter next  ·  Esc back")
}

// handleDNSWorkersScreen picks the worker-pool size and launches the scan.
func (m tuiModel) handleDNSWorkersScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(dnsWorkerPresets)-1 {
			m.cursor++
		}
	case "esc":
		m.goBack()
	case "enter":
		p := dnsWorkerPresets[m.cursor]
		m.dnsConcurrency = p.workers
		m.addLog(fmt.Sprintf("DNS scan workers: %d", p.workers))
		m.pushScreen(screenDNSNearby)
		m.cursor = 0 // default to "No"
	}
	return m, nil
}

// viewDNSWorkers renders the worker-count picker using the shared list style.
func (m tuiModel) viewDNSWorkers(w, h int) string {
	items := make([]string, len(dnsWorkerPresets))
	for i, p := range dnsWorkerPresets {
		items[i] = p.label
	}
	return m.viewList(w, h, "DNS SCAN WORKERS", items,
		"↑↓ navigate  ·  Enter next  ·  Esc back")
}

// handleDNSNearbyScreen picks the nearby-expansion setting and launches the scan.
func (m tuiModel) handleDNSNearbyScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(dnsNearbyPresets)-1 {
			m.cursor++
		}
	case "esc":
		m.goBack()
	case "enter":
		p := dnsNearbyPresets[m.cursor]
		m.dnsTestNearby = p.enable
		if p.enable {
			m.addLog("DNS scan: Test Nearby IPs enabled (expands /24 around tunnel-ready hits)")
		} else {
			m.addLog("DNS scan: Test Nearby IPs disabled")
		}
		return m.launchDNSScan(m.scanConfig.Targets)
	}
	return m, nil
}

// viewDNSNearby renders the nearby-expansion picker using the shared list style.
func (m tuiModel) viewDNSNearby(w, h int) string {
	items := make([]string, len(dnsNearbyPresets))
	for i, p := range dnsNearbyPresets {
		items[i] = p.label
	}
	return m.viewList(w, h, "TEST NEARBY IPs", items,
		"↑↓ navigate  ·  Enter start scan  ·  Esc back")
}

// launchDNSScan is invoked from the shared target-selection flow (ASN / paste /
// type / file import → review) once resolver targets are chosen. It reuses the
// standard scanMsgCh + screenScanning + screenScanResults machinery, so the DNS
// feature behaves exactly like the other scans.
func (m tuiModel) launchDNSScan(targets []string) (tuiModel, tea.Cmd) {
	workers := m.dnsConcurrency
	if workers <= 0 {
		workers = defaultDNSWorkers
	}
	m.dnsConcurrency = workers
	m.startOperation() // pushes screenScanning + fresh scanCtx/counters
	m.scanMsgCh = make(chan tea.Msg, 65536)
	m.startScanLogFile("dnsscan", targets, nil, workers, 3*time.Second)
	m.addLog(fmt.Sprintf("Starting DNS resolver/tunnel scan: targets=%d workers=%d", len(targets), workers))
	return m, m.cmdDNSScan(targets)
}

// cmdDNSScan runs the resolver scan on a background goroutine: it streams
// per-resolver progress + full header dumps to the activity log, optionally
// expands the /24 around tunnel-ready hits ("Test Nearby IPs"), dumps txt/csv/
// json reports into the "dns scan" output folder, and returns the tunnel-ready
// shortlist (best score first) as the final result set.
func (m tuiModel) cmdDNSScan(targets []string) tea.Cmd {
	ch := m.scanMsgCh
	if ch == nil {
		ch = make(chan tea.Msg, 65536)
	}
	runCtx := m.scanCtx
	dataDir := m.app.DataDir

	// Transport + ports chosen on the DNS port screen (default: UDP+TCP/53).
	protocol := m.dnsProtocol
	if protocol == "" {
		protocol = "both"
	}
	ports := append([]int(nil), m.scanConfig.Ports...)
	if len(ports) == 0 {
		ports = []int{53}
	}

	workers := m.dnsConcurrency
	if workers <= 0 {
		workers = defaultDNSWorkers
	}
	testNearby := m.dnsTestNearby
	reference := m.dnsReference
	if reference == "" {
		reference = dnsscan.ReferenceGoogle
	}

	return tea.Batch(
		func() tea.Msg {
			t0 := time.Now()
			if runCtx == nil {
				runCtx = context.Background()
			}

			ips := tlsprobe.ExpandTargets(targets)
			if len(ips) == 0 {
				ips = targets
			}
			total := len(ips)
			start := time.Now()

			trySend := func(msg tea.Msg) {
				select {
				case ch <- msg:
				case <-time.After(50 * time.Millisecond):
				}
			}

			trySend(logMsg{text: fmt.Sprintf("[DNS] scanning %d resolver(s): headers + score + tunnel suitability", total)})
			trySend(scanProgressMsg{current: 0, total: total, startTime: start, totalIPs: total})

			opts := dnsscan.Options{
				TargetDomain:  "google.com",
				Timeout:       3 * time.Second,
				Concurrency:   workers,
				Protocol:      protocol,
				Ports:         ports,
				TestNearby:    testNearby,
				TruthProvider: reference,
			}

			var mu sync.Mutex
			hits := 0
			progress := func(done, tot int, r dnsscan.ResolverResult) {
				status := "no-response"
				if r.Responded {
					status = fmt.Sprintf("resp %dms", r.BestLatency.Milliseconds())
				}
				trySend(logMsg{text: fmt.Sprintf("%-21s %-13s score=%d/6 RA=%v EDNS=%v POISON=%v TXT=%v TRANSP=%v TUNNEL=%v (%s)",
					r.IP, status, r.Score, r.RA, r.EDNS, r.Poisoned, r.TxtPass, r.Transparent, r.TunnelReady, r.TunnelReason)})
				for _, hd := range r.HeaderDump() {
					trySend(logMsg{text: "    " + hd})
				}
				mu.Lock()
				if r.TunnelReady {
					hits++
				}
				h := hits
				mu.Unlock()
				trySend(scanProgressMsg{current: done, total: tot, hits: h, startTime: start, currentIP: r.IP, totalIPs: tot})
			}

			all := dnsscan.ScanResolvers(runCtx, ips, opts, progress)

			// Test Nearby IPs: expand the /24 around each tunnel-ready resolver
			// and rescan the addresses we haven't already tried.
			if opts.TestNearby && runCtx.Err() == nil {
				scanned := make(map[string]struct{}, len(ips))
				for _, ip := range ips {
					scanned[ip] = struct{}{}
				}
				var nearby []string
				for _, r := range all {
					if !r.TunnelReady {
						continue
					}
					for _, nip := range dnsscan.NearbyIPs(r.IP) {
						if _, ok := scanned[nip]; ok {
							continue
						}
						scanned[nip] = struct{}{}
						nearby = append(nearby, nip)
					}
				}
				if len(nearby) > 0 {
					trySend(logMsg{text: fmt.Sprintf("[DNS] Test Nearby IPs: expanding %d address(es) around tunnel-ready hits", len(nearby))})
					base := len(ips)
					nprogress := func(done, tot int, r dnsscan.ResolverResult) {
						progress(base+done, base+tot, r)
					}
					nres := dnsscan.ScanResolvers(runCtx, nearby, opts, nprogress)
					for i := range nres {
						nres[i].Nearby = true
					}
					all = append(all, nres...)
				}
			}

			// Dump every result to the "dns scan" folder (txt + csv + json).
			outDir := filepath.Join(dataDir, "dns scan")
			if paths, err := dnsscan.WriteReports(outDir, all); err != nil {
				trySend(logMsg{text: "[DNS] report write failed: " + err.Error()})
			} else {
				trySend(logMsg{text: "[DNS] reports written to " + paths.Dir})
				trySend(logMsg{text: "    " + filepath.Base(paths.Full) + " / " + filepath.Base(paths.Passed) + " / " + filepath.Base(paths.CSV) + " / " + filepath.Base(paths.XLSX) + " / " + filepath.Base(paths.HTML) + " / " + filepath.Base(paths.JSON)})
			}

			// Build the on-screen shortlist (tunnel-ready, best score first).
			var tunnelReady []string
			for _, r := range all {
				if !r.TunnelReady {
					continue
				}
				tag := ""
				if r.Nearby {
					tag = " [nearby]"
				}
				tunnelReady = append(tunnelReady, fmt.Sprintf("%-21s score=%d/6 poison=%v transparent=%v%s",
					r.IP, r.Score, r.Poisoned, r.Transparent, tag))
			}
			trySend(logMsg{text: fmt.Sprintf("[DNS] done: %d tunnel-ready of %d scanned", len(tunnelReady), len(all))})
			close(ch)

			if err := runCtx.Err(); err != nil {
				return poolOperationCompleteMsg{operationType: "dns_scan", results: tunnelReady, err: err, duration: time.Since(t0)}
			}
			if len(tunnelReady) == 0 {
				tunnelReady = []string{"No tunnel-ready resolvers found (see 'dns scan' folder + activity log)"}
			}
			return poolOperationCompleteMsg{operationType: "dns_scan", results: tunnelReady, duration: time.Since(t0)}
		},
		waitForScanMessage(ch),
	)
}
