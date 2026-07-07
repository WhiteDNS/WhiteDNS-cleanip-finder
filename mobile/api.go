package mobile

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/asnexport"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/tlsprobe"
)

// ── throttle ─────────────────────────────────────────────────────────────────
// Allows at most one event per periodMs. Lock-free (atomic CAS on timestamp).

type throttle struct {
	lastMs   atomic.Int64
	periodMs int64
}

func newThrottle(period time.Duration) *throttle {
	return &throttle{periodMs: period.Milliseconds()}
}

func (t *throttle) allow() bool {
	now := time.Now().UnixMilli()
	last := t.lastMs.Load()
	if now-last < t.periodMs {
		return false
	}
	return t.lastMs.CompareAndSwap(last, now)
}

// ── resultFile ───────────────────────────────────────────────────────────────
// Opened once at scan start, appended to for every accepted result, closed at
// scan end. This keeps memory flat regardless of how many results arrive.

type resultFile struct {
	f    *os.File
	w    *bufio.Writer
	path string
	// Companion file containing ONLY the ip:port of each passed result (no probe
	// domains or extra columns) — a clean list ready to paste elsewhere.
	ipF    *os.File
	ipW    *bufio.Writer
	ipPath string
}

// ipPortRegex matches the first IPv4 (with optional :port) in a result line, so
// the clean ip:port list works for every scan's line format (plain "ip:port",
// SNI "host ip:port OK …", Speed-Rank "N. ip DOWN …", proxy "http ip:port …").
var ipPortRegex = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)

func openResultFile(dataDir, kind string) (*resultFile, error) {
	stamp := time.Now().Format("20060102-150405")
	dir := filepath.Join(dataDir, "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, fmt.Sprintf("scan-%s-%s.txt", kind, stamp))
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	rf := &resultFile{f: f, w: bufio.NewWriterSize(f, 32*1024), path: p}
	// Best-effort companion ip:port-only file; if it can't be created the main
	// results file still works.
	ipP := filepath.Join(dir, fmt.Sprintf("scan-%s-%s-ipport.txt", kind, stamp))
	if ipF, ierr := os.Create(ipP); ierr == nil {
		rf.ipF = ipF
		rf.ipW = bufio.NewWriterSize(ipF, 16*1024)
		rf.ipPath = ipP
	}
	return rf, nil
}

func (rf *resultFile) write(line string) {
	if rf == nil {
		return
	}
	_, _ = fmt.Fprintln(rf.w, line)
	if rf.ipW != nil {
		if ipPort := ipPortRegex.FindString(line); ipPort != "" {
			_, _ = fmt.Fprintln(rf.ipW, ipPort)
		}
	}
}

// flush persists buffered results to disk without closing the file. Called after
// each chunk so passed IPs survive even if the app is killed mid-scan.
func (rf *resultFile) flush() {
	if rf == nil {
		return
	}
	_ = rf.w.Flush()
	_ = rf.f.Sync()
	if rf.ipW != nil {
		_ = rf.ipW.Flush()
		_ = rf.ipF.Sync()
	}
}

func (rf *resultFile) close() string {
	if rf == nil {
		return ""
	}
	_ = rf.w.Flush()
	_ = rf.f.Close()
	if rf.ipW != nil {
		_ = rf.ipW.Flush()
		_ = rf.ipF.Close()
	}
	return rf.path
}

// ── logFile ──────────────────────────────────────────────────────────────────
// Persists the scan's activity log to {dataDir}/logs/. Called from many probe
// goroutines, so writes are mutex-guarded. Very verbose engine lines (per-IP
// DEBUG/TRACE/SKIP/PROGRESS) are filtered out to keep the file manageable.

type logFile struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	path string
}

func openLogFile(dataDir, kind string) *logFile {
	stamp := time.Now().Format("20060102-150405")
	p := filepath.Join(dataDir, "logs", fmt.Sprintf("scan-%s-%s.log", kind, stamp))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil
	}
	f, err := os.Create(p)
	if err != nil {
		return nil
	}
	return &logFile{f: f, w: bufio.NewWriterSize(f, 16*1024), path: p}
}

var verboseLogTags = []string{"[DEBUG]", "[TRACE]", "[SKIP]", "[PROGRESS]"}

func (lf *logFile) write(line string) {
	if lf == nil {
		return
	}
	for _, tag := range verboseLogTags {
		if strings.Contains(line, tag) {
			return // skip very chatty lines
		}
	}
	lf.mu.Lock()
	_, _ = fmt.Fprintln(lf.w, line)
	lf.mu.Unlock()
}

func (lf *logFile) close() {
	if lf == nil {
		return
	}
	lf.mu.Lock()
	_ = lf.w.Flush()
	_ = lf.f.Close()
	lf.mu.Unlock()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func splitTargets(blob string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		appendTargetLine(&out, line, 0)
	}
	return out
}

func appendTargetLine(out *[]string, line string, depth int) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if strings.HasPrefix(line, "@") {
		appendTargetsFromFile(out, strings.TrimSpace(strings.TrimPrefix(line, "@")), depth+1)
		return
	}
	for _, f := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ','
	}) {
		if f = strings.TrimSpace(f); f != "" {
			*out = append(*out, f)
		}
	}
}

func appendTargetsFromFile(out *[]string, path string, depth int) {
	if depth > 3 {
		return
	}
	path = strings.Trim(path, `"'`)
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	fileScanner := bufio.NewScanner(f)
	fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for fileScanner.Scan() {
		appendTargetLine(out, fileScanner.Text(), depth)
	}
}

func parsePortsCSV(portStr string) []int {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rng := strings.SplitN(part, "-", 2)
			s, _ := strconv.Atoi(strings.TrimSpace(rng[0]))
			e, _ := strconv.Atoi(strings.TrimSpace(rng[1]))
			for p := s; p <= e; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	if len(ports) == 0 {
		return []int{80, 443, 8080}
	}
	sort.Ints(ports)
	return ports
}

func parsePortsOrEmpty(portStr string) []int {
	if strings.TrimSpace(portStr) == "" {
		return nil
	}
	return parsePortsCSV(portStr)
}

func timeoutOrDefault(ms int, def time.Duration, lowBandwidth bool) time.Duration {
	t := def
	if ms > 0 {
		t = time.Duration(ms) * time.Millisecond
	}
	if lowBandwidth && t < 15*time.Second {
		t = 15 * time.Second
	}
	return t
}

func forceLiteRuntime() bool {
	return runtime.GOOS == "android" && (runtime.GOARCH == "arm" || runtime.GOARCH == "386")
}

func effectiveLiteMode(cfg *ScanConfig) bool {
	return (cfg != nil && cfg.LiteMode) || forceLiteRuntime()
}

func effectiveLowBandwidth(cfg *ScanConfig, liteMode bool) bool {
	return (cfg != nil && cfg.LowBandwidth) || liteMode
}

// concurrencyOrDefault keeps worker counts phone-safe. High fanout on a phone
// saturates the radio/fd table and disconnects the device, so we hard-cap well
// below desktop values.
func concurrencyOrDefault(c, def int) int {
	if c <= 0 {
		c = def
	}
	// Mobile hard cap: 100 workers. Even this is high for a weak device; the
	// recommended modes are 10/25/50.
	if c > 100 {
		c = 100
	}
	if c < 1 {
		c = 1
	}
	return c
}

// Chunked-scan parameters. Instead of expanding every CIDR into RAM (which
// OOM-crashes on CDN-sized ranges), the IP scan streams all IPs to a file on
// disk, then scans them back a chunk at a time. This keeps RAM flat while
// preserving FULL coverage — no CIDRs or IPs are dropped.
const (
	chunkIPCount  = 4000  // IPs scanned per chunk (bounds per-chunk RAM)
	perCIDRMaxIPs = 65536 // matches the desktop engine's per-CIDR expansion cap

	// Lite mode (old / low-RAM devices): much smaller chunks and a hard low
	// concurrency cap to keep peak memory, fd usage and CPU minimal.
	liteChunkIPCount       = 512
	liteChunkEndpointCount = 1024
	liteMaxConcurrency     = 8

	// Staging de-duplication set caps (the only RAM cost while expanding targets
	// to disk). Normal mode dedups up to ~400k unique IPs (~25 MB); Lite mode
	// disables the staging set so big ASNs stage with almost no RAM on weak devices.
	stageDedupCap = 400_000
	liteDedupCap  = 0
)

// interChunkPause returns a short delay inserted between chunks so the scan does
// not hold the radio saturated continuously — gentler on the user's connection.
func interChunkPause(conc int) time.Duration {
	switch {
	case conc <= 10:
		return 500 * time.Millisecond
	case conc <= 25:
		return 250 * time.Millisecond
	case conc <= 50:
		return 100 * time.Millisecond
	default:
		return 0
	}
}

func calcETA(start time.Time, processed, total int) int {
	if processed <= 0 || processed >= total {
		return 0
	}
	rate := float64(processed) / time.Since(start).Seconds()
	if rate <= 0 {
		return 0
	}
	return int(float64(total-processed) / rate)
}

// etaTracker estimates remaining time from the RECENT scan rate rather than the
// cumulative average since start. The cumulative average is badly skewed by the
// slow warm-up (health check, TLS handshakes, the first timeouts), which makes
// the ETA read absurdly high (e.g. "3000m") for the first minute. A sliding
// window over the last ~30s reflects the true steady-state pace.
type etaTracker struct {
	mu      sync.Mutex
	times   []time.Time
	counts  []int
	windowS float64
}

func newETATracker() *etaTracker { return &etaTracker{windowS: 30} }

func (e *etaTracker) eta(done, total int) int {
	if done <= 0 || done >= total {
		return 0
	}
	now := time.Now()
	e.mu.Lock()
	e.times = append(e.times, now)
	e.counts = append(e.counts, done)
	// Drop samples older than the window, always keeping at least one anchor.
	cutoff := now.Add(-time.Duration(e.windowS) * time.Second)
	drop := 0
	for drop < len(e.times)-1 && e.times[drop].Before(cutoff) {
		drop++
	}
	e.times = e.times[drop:]
	e.counts = e.counts[drop:]
	t0, c0 := e.times[0], e.counts[0]
	e.mu.Unlock()

	dt := now.Sub(t0).Seconds()
	dc := done - c0
	if dt <= 0 || dc <= 0 {
		return 0
	}
	rate := float64(dc) / dt // endpoints per second over the recent window
	return int(float64(total-done) / rate)
}

// ── IP / CIDR scan ───────────────────────────────────────────────────────────

// StartIPScan scans IP ranges with FULL coverage but flat memory. It streams
// every expanded IP to a temp file on disk, then scans the file back in small
// chunks — so a Cloudflare-sized range can be scanned without OOM-crashing the
// device. Results are written to {dataDir}/results/scan-ip-*.txt incrementally
// (so a stopped scan still keeps what it found).
func StartIPScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50) // phone default: 50 workers
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, lowBandwidth)

	// Lite mode for old / low-RAM devices: smaller chunks, far lower concurrency,
	// sequential per-IP domain probing, and inter-chunk pauses. This keeps peak
	// memory, open file descriptors, and CPU low enough that the scan doesn't
	// OOM/ANR-crash on weak hardware. Coverage is unchanged — only resource use.
	chunkSize := chunkIPCount
	if liteMode {
		chunkSize = liteChunkIPCount
		if len(ports) > 0 {
			chunkSize = liteChunkEndpointCount / len(ports)
			if chunkSize < 1 {
				chunkSize = 1
			}
			if chunkSize > liteChunkIPCount {
				chunkSize = liteChunkIPCount
			}
		}
		if conc > liteMaxConcurrency {
			conc = liteMaxConcurrency
		}
	}

	sc.SetTargetPorts(ports)
	sc.SetVerboseProbeLogging(cfg.VerboseLog)

	lf := openLogFile(dataDir, "ip")
	logThrottle := newThrottle(250 * time.Millisecond)
	sc.SetLogCallback(func(msg string) {
		line := strings.TrimRight(msg, "\n")
		lf.write(line) // persist activity log to disk (filtered)
		if !h.isStopped() && logThrottle.allow() {
			l.OnLog(line)
		}
	})

	// Per-chunk options. DisableAutoConcurrency keeps worker count phone-safe.
	// No MaxIPs/MaxEndpoints caps — coverage is full; chunking bounds memory.
	//
	// Bandwidth is reduced WITHOUT changing results: lower worker concurrency,
	// inter-chunk pauses, and (for gentle/low-bandwidth modes) probing the
	// endpoint's domains one-at-a-time (AdaptiveDomainConcurrency=1). The full
	// probe-domain list is always used, so the same endpoints are found.
	makeOpts := func() scanner.IPScanOptions {
		o := scanner.IPScanOptions{
			Ports:                  ports,
			Concurrency:            conc,
			Timeout:                timeout,
			LowBandwidth:           lowBandwidth,
			DisableAutoConcurrency: true,
		}
		if conc <= 25 || lowBandwidth || liteMode {
			o.AdaptiveDomainConcurrency = 1
		}
		return o
	}

	go func() {
		defer sc.SetLogCallback(nil)
		defer lf.close()

		// 1. Stream-expand all CIDRs/IPs to a temp file (low RAM, full coverage).
		// Lite mode uses a tiny dedup set so even huge ASNs stage with minimal RAM
		// (a single ASN has no internal duplicates, so nothing is lost).
		dedupCap := stageDedupCap
		if liteMode {
			dedupCap = liteDedupCap
		}
		tmpPath := filepath.Join(dataDir, "tmp", fmt.Sprintf("targets-%d.txt", time.Now().UnixNano()))
		totalIPs, err := expandTargetsToFile(targets, tmpPath, dedupCap)
		if err != nil {
			l.OnDone("", "could not stage targets: "+err.Error())
			return
		}
		defer os.Remove(tmpPath)
		if totalIPs == 0 {
			l.OnDone("", "no IPs expanded from CIDRs")
			return
		}
		stagedMsg := fmt.Sprintf("[IP-SCAN-START] targets=%d staged_ips=%d ports=%d total_probes=%d concurrency=%d lite=%v low_bandwidth=%v",
			len(targets), totalIPs, len(ports), totalIPs*len(ports), conc, liteMode, lowBandwidth)
		lf.write(stagedMsg)
		l.OnLog(stagedMsg)

		file, err := os.Open(tmpPath)
		if err != nil {
			l.OnDone("", err.Error())
			return
		}
		defer file.Close()

		rf, _ := openResultFile(dataDir, "ip")
		resultThrottle := newThrottle(250 * time.Millisecond)
		totalEndpoints := totalIPs * len(ports)
		start := time.Now()
		etaEst := newETATracker()
		processedBase := 0 // endpoints fully scanned in prior chunks
		foundTotal := 0
		pause := interChunkPause(conc)

		// 2. Scan one chunk of IPs, writing accepted results to disk as we go.
		runChunk := func(chunk []string) {
			if len(chunk) == 0 {
				return
			}
			progressCb := func(processed, _ /*totalProbes*/, accepted int, currentIP string, _ int) {
				if !h.isStopped() {
					done := processedBase + processed
					l.OnProgress(done, totalEndpoints, foundTotal+accepted, totalIPs,
						currentIP, etaEst.eta(done, totalEndpoints))
				}
			}
			results, scanErr := sc.ScanIPsWithProgress(chunk, makeOpts(), progressCb)
			if scanErr == nil {
				for _, r := range results {
					rf.write(r)
					if resultThrottle.allow() {
						l.OnResult(r)
					}
				}
				foundTotal += len(results)
			}
			rf.flush() // persist this chunk's passed IPs immediately (survives a kill)
			processedBase += len(chunk) * len(ports)
		}

		// 3. Read the staged IP file chunk by chunk.
		fileScanner := bufio.NewScanner(file)
		fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		chunk := make([]string, 0, chunkSize)
		for fileScanner.Scan() {
			if h.isStopped() {
				break
			}
			for h.isPaused() && !h.isStopped() {
				time.Sleep(200 * time.Millisecond)
			}
			line := strings.TrimSpace(fileScanner.Text())
			if line == "" {
				continue
			}
			chunk = append(chunk, line)
			if len(chunk) >= chunkSize {
				runChunk(chunk)
				chunk = chunk[:0]
				if liteMode {
					// Reclaim the chunk's memory promptly so peak RAM stays low on
					// weak devices, then breathe before the next chunk.
					runtime.GC()
					time.Sleep(300 * time.Millisecond)
				} else if pause > 0 && !h.isStopped() {
					time.Sleep(pause) // ease bandwidth between chunks
				}
			}
		}
		if !h.isStopped() {
			runChunk(chunk) // final partial chunk
		}

		// Whether the scan finished or was stopped, partial results are already on
		// disk — report success with the saved path so the Results screen shows
		// them (a user-initiated stop is not an error).
		reason := "completed"
		if h.isStopped() {
			reason = "stopped"
		}
		endMsg := fmt.Sprintf("[IP-SCAN-END] reason=%s staged_ips=%d processed_endpoints=%d/%d found=%d elapsed=%s",
			reason, totalIPs, processedBase, totalEndpoints, foundTotal, time.Since(start).Round(time.Second))
		lf.write(endMsg)
		l.OnLog(endMsg)

		savedPath := rf.close()
		l.OnDone(savedPath, "")
	}()
	return h
}

// expandTargetsToFile streams every IP from the given CIDRs/IPs to path, one per
// line, without holding the full set in RAM. ip:port targets and bare IPs pass
// through unchanged. Each CIDR is capped at perCIDRMaxIPs (matching the desktop
// engine) so a single huge prefix can't fill the disk. Returns the line count.
// expandTargetsToFile streams every IP to path. dedupCap bounds the size of the
// de-duplication set (its only RAM cost): once reached, the rest is emitted
// unfiltered so memory can never blow up. A single ASN's CIDRs don't overlap,
// so its dedup set finds nothing — Lite mode therefore passes a tiny cap (or 0
// to disable) to stage huge ASNs with almost no RAM, WITHOUT dropping any IPs.
func expandTargetsToFile(targets []string, path string, dedupCap int) (int, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriterSize(f, 64*1024)
	count := 0
	// De-duplicate addresses so overlapping CIDRs/ASNs (e.g. selecting both a /16
	// and a /24 inside it) don't scan the same IP twice. Result-neutral — only
	// redundant work is skipped. dedupCap <= 0 disables it entirely (lowest RAM).
	var seen map[string]struct{}
	if dedupCap > 0 {
		seen = make(map[string]struct{}, 1024)
	}
	emit := func(line string) {
		if seen != nil && len(seen) < dedupCap {
			if _, dup := seen[line]; dup {
				return
			}
			seen[line] = struct{}{}
		}
		fmt.Fprintln(w, line)
		count++
	}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		// ip:port passthrough
		if host, _, err := net.SplitHostPort(t); err == nil && net.ParseIP(host) != nil {
			emit(t)
			continue
		}
		// bare IP
		if net.ParseIP(t) != nil {
			emit(t)
			continue
		}
		// CIDR — stream each address
		_, ipnet, perr := net.ParseCIDR(t)
		if perr != nil {
			continue
		}
		cur := make(net.IP, len(ipnet.IP))
		copy(cur, ipnet.IP.Mask(ipnet.Mask))
		emitted := 0
		for ipnet.Contains(cur) && emitted < perCIDRMaxIPs {
			emit(cur.String())
			emitted++
			incIP(cur)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return count, err
	}
	return count, f.Close()
}

func expandTargetsLimited(targets []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	emit := func(ip string) bool {
		if ip == "" {
			return len(out) >= limit
		}
		if _, ok := seen[ip]; ok {
			return len(out) >= limit
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
		return len(out) >= limit
	}

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(t); err == nil && net.ParseIP(host) != nil {
			if emit(host) {
				break
			}
			continue
		}
		if net.ParseIP(t) != nil {
			if emit(t) {
				break
			}
			continue
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			continue
		}
		cur := make(net.IP, len(ipnet.IP))
		copy(cur, ipnet.IP.Mask(ipnet.Mask))
		emitted := 0
		for ipnet.Contains(cur) && emitted < perCIDRMaxIPs {
			if emit(cur.String()) {
				return out
			}
			emitted++
			incIP(cur)
		}
	}
	return out
}

// incIP increments an IP address (big-endian) by one, in place.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ── HTTP / SOCKS5 proxy scans ────────────────────────────────────────────────

func startProxyScan(dataDir, kind string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	if liteMode && conc > liteMaxConcurrency {
		conc = liteMaxConcurrency
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 8*time.Second, lowBandwidth)

	opts := scanner.ProxyScanOptions{
		Ports:         parsePortsOrEmpty(cfg.Ports),
		Discovery:     "direct",
		Concurrency:   conc,
		Timeout:       timeout,
		TransferModel: strings.TrimSpace(cfg.TransferModel),
		LiteMode:      liteMode,
	}

	logThrottle := newThrottle(250 * time.Millisecond)
	sc.SetLogCallback(func(msg string) {
		if !h.isStopped() && logThrottle.allow() {
			l.OnLog(strings.TrimRight(msg, "\n"))
		}
	})

	start := time.Now()
	sc.SetProxyProgressCallback(func(processed, total, hits int, currentIP string, totalIPs int) {
		if !h.isStopped() {
			l.OnProgress(processed, total, hits, totalIPs, currentIP,
				calcETA(start, processed, total))
		}
	})

	go func() {
		defer func() {
			sc.SetLogCallback(nil)
			sc.SetProxyProgressCallback(nil)
		}()

		var results []string
		var err error
		if kind == "socks5" {
			results, err = sc.ScanSOCKS5Proxies(targets, opts)
		} else {
			results, err = sc.ScanHTTPProxies(targets, opts)
		}

		// Only a real engine error is fatal. A user-initiated stop is NOT an error:
		// the scan returns whatever it found so far, and we persist it so the user
		// never loses partial results by stopping (there is no manual save on phone).
		if err != nil {
			l.OnDone("", err.Error())
			return
		}

		rf, _ := openResultFile(dataDir, kind)
		resultThrottle := newThrottle(250 * time.Millisecond)
		stopped := h.isStopped()
		for _, r := range results {
			rf.write(r)
			if !stopped && resultThrottle.allow() {
				l.OnResult(r)
			}
		}
		l.OnDone(rf.close(), "")
	}()
	return h
}

// StartHTTPProxyScan begins a direct HTTP-proxy scan.
func StartHTTPProxyScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "http", cfg, l)
}

// StartSOCKS5Scan begins a direct SOCKS5-proxy scan.
func StartSOCKS5Scan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "socks5", cfg, l)
}

// ── SNI scan ─────────────────────────────────────────────────────────────────

// StartSNIScan probes TLS/SNI. Each successful result is written to disk
// immediately; only a throttled sample goes to the listener.
func StartSNIScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)
	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	domains := splitTargets(cfg.SNIDomains)
	if len(domains) == 0 {
		domains = tlsprobe.GetDomains(dataDir)
	}
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	if liteMode && conc > liteMaxConcurrency {
		conc = liteMaxConcurrency
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, lowBandwidth)

	go func() {
		if len(targets) == 0 || len(domains) == 0 {
			reason := "no IP targets selected"
			if len(domains) == 0 {
				reason = "no SNI domains selected"
			}
			l.OnDone("", reason)
			return
		}
		if liteMode {
			runLiteSNIScan(dataDir, cfg, l, h, targets, domains, ports, conc, timeout)
			return
		}

		rf, _ := openResultFile(dataDir, "sni")
		logThrottle := newThrottle(250 * time.Millisecond)
		resultThrottle := newThrottle(250 * time.Millisecond)

		resCh := make(chan tlsprobe.ProbeResult, 512)
		go func() {
			tlsprobe.RunScanContext(h.ctx, tlsprobe.ScanConfig{
				Targets:     targets,
				Hostnames:   domains,
				Port:        ports[0],
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
				PauseFunc:   h.isPaused,
			}, resCh, nil)
		}()

		expanded := len(tlsprobe.ExpandTargets(targets))
		if expanded == 0 {
			expanded = len(targets)
		}
		total := expanded * len(domains)
		start := time.Now()
		processed, hits := 0, 0

		for pr := range resCh {
			processed++
			if h.isStopped() {
				continue // drain so producer goroutine can finish
			}

			label := "FAIL"
			if pr.Success {
				label = "OK"
				hits++
			}
			suffix := ""
			if pr.CertMatchesSNI {
				suffix = " [cert-match]"
			} else if pr.SNIAccepted {
				suffix = " [sni-ok]"
			}
			text := fmt.Sprintf("%s %s:%d %s %dms %s %d%s",
				pr.Hostname, pr.IP, pr.Port, label,
				int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus, suffix)

			if pr.Success {
				rf.write(text)
				if resultThrottle.allow() {
					l.OnResult(text)
				}
			}
			if logThrottle.allow() {
				l.OnLog(text)
			}
			l.OnProgress(processed, total, hits, expanded, pr.IP,
				calcETA(start, processed, total))
		}

		// A stop is not an error: SNI passes are written to disk as they are found,
		// so return the saved path (not an error) and keep the partial results.
		l.OnDone(rf.close(), "")
	}()
	return h
}

// ── Speed & Loss rank ────────────────────────────────────────────────────────

func runLiteSNIScan(dataDir string, cfg *ScanConfig, l ScanListener, h *ScanHandle, targets, domains []string, ports []int, conc int, timeout time.Duration) {
	chunkSize := liteChunkIPCount
	if len(domains) > 0 {
		chunkSize = liteChunkEndpointCount / len(domains)
		if chunkSize < 1 {
			chunkSize = 1
		}
		if chunkSize > liteChunkIPCount {
			chunkSize = liteChunkIPCount
		}
	}

	tmpPath := filepath.Join(dataDir, "tmp", fmt.Sprintf("sni-targets-%d.txt", time.Now().UnixNano()))
	totalIPs, err := expandTargetsToFile(targets, tmpPath, liteDedupCap)
	if err != nil {
		l.OnDone("", "could not stage SNI targets: "+err.Error())
		return
	}
	defer os.Remove(tmpPath)
	if totalIPs == 0 {
		l.OnDone("", "no IP targets selected")
		return
	}

	file, err := os.Open(tmpPath)
	if err != nil {
		l.OnDone("", err.Error())
		return
	}
	defer file.Close()

	rf, _ := openResultFile(dataDir, "sni")
	logThrottle := newThrottle(250 * time.Millisecond)
	resultThrottle := newThrottle(250 * time.Millisecond)
	total := totalIPs * len(domains)
	start := time.Now()
	processed, hits := 0, 0

	l.OnLog(fmt.Sprintf("[SNI-LITE-START] targets=%d staged_ips=%d domains=%d total_probes=%d concurrency=%d",
		len(targets), totalIPs, len(domains), total, conc))

	runChunk := func(chunk []string) {
		if len(chunk) == 0 || h.isStopped() {
			return
		}
		resCh := make(chan tlsprobe.ProbeResult, 128)
		go func() {
			tlsprobe.RunScanContext(h.ctx, tlsprobe.ScanConfig{
				Targets:     chunk,
				Hostnames:   domains,
				Port:        ports[0],
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
				PauseFunc:   h.isPaused,
			}, resCh, nil)
		}()

		for pr := range resCh {
			processed++
			if h.isStopped() {
				continue
			}

			label := "FAIL"
			if pr.Success {
				label = "OK"
				hits++
			}
			suffix := ""
			if pr.CertMatchesSNI {
				suffix = " [cert-match]"
			} else if pr.SNIAccepted {
				suffix = " [sni-ok]"
			}
			text := fmt.Sprintf("%s %s:%d %s %dms %s %d%s",
				pr.Hostname, pr.IP, pr.Port, label,
				int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus, suffix)

			if pr.Success {
				rf.write(text)
				if resultThrottle.allow() {
					l.OnResult(text)
				}
			}
			if logThrottle.allow() {
				l.OnLog(text)
			}
			l.OnProgress(processed, total, hits, totalIPs, pr.IP,
				calcETA(start, processed, total))
		}
		rf.flush()
	}

	fileScanner := bufio.NewScanner(file)
	fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	chunk := make([]string, 0, chunkSize)
	for fileScanner.Scan() {
		if h.isStopped() {
			break
		}
		for h.isPaused() && !h.isStopped() {
			time.Sleep(200 * time.Millisecond)
		}
		line := strings.TrimSpace(fileScanner.Text())
		if line == "" {
			continue
		}
		chunk = append(chunk, line)
		if len(chunk) >= chunkSize {
			runChunk(chunk)
			chunk = chunk[:0]
			runtime.GC()
			time.Sleep(300 * time.Millisecond)
		}
	}
	if !h.isStopped() {
		runChunk(chunk)
	}

	reason := "completed"
	if h.isStopped() {
		reason = "stopped"
	}
	l.OnLog(fmt.Sprintf("[SNI-LITE-END] reason=%s staged_ips=%d processed=%d/%d hits=%d elapsed=%s",
		reason, totalIPs, processed, total, hits, time.Since(start).Round(time.Second)))
	l.OnDone(rf.close(), "")
}

// maxSpeedRankIPs caps how many IPs are benchmarked on a phone. The speed test
// downloads/uploads several MB per IP, so this is intentionally small — the
// feature is meant to rank an already-passed clean-IP shortlist, not a CIDR.
const maxSpeedRankIPs = 256

// StartSpeedRankScan benchmarks each target IP via the Cloudflare speed test
// (with Google generate_204 and Cachefly as fallbacks) and ranks them by a
// composite of download/upload throughput, packet loss, and latency. Results
// are written best-first to {dataDir}/results/scan-speedrank-*.txt and a CSV is
// saved alongside. Mirrors the desktop TUI "Speed & Loss Rank" scan.
func StartSpeedRankScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	ports := parsePortsOrEmpty(cfg.Ports)
	port := 443
	if len(ports) > 0 && ports[0] > 0 {
		port = ports[0]
	}
	conc := concurrencyOrDefault(cfg.Concurrency, 16)
	if liteMode && conc > 4 {
		conc = 4
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 12*time.Second, lowBandwidth)

	go func() {
		var ips []string
		if liteMode {
			ips = expandTargetsLimited(targets, maxSpeedRankIPs)
		} else {
			ips = tlsprobe.ExpandTargets(targets)
		}
		if len(ips) == 0 {
			ips = targets
		}
		if len(ips) == 0 {
			l.OnDone("", "no IP targets selected")
			return
		}
		if len(ips) > maxSpeedRankIPs {
			l.OnLog(fmt.Sprintf("[SPEEDRANK] %d IPs given; benchmarking the first %d (speed test is heavy)", len(ips), maxSpeedRankIPs))
			ips = ips[:maxSpeedRankIPs]
		}

		rf, _ := openResultFile(dataDir, "speedrank")
		resultThrottle := newThrottle(250 * time.Millisecond)
		start := time.Now()
		total := len(ips)
		l.OnLog(fmt.Sprintf("[SPEEDRANK] Benchmarking %d IP(s) via speed.cloudflare.com + fallbacks (port %d, concurrency %d)", total, port, conc))

		opts := scanner.SpeedRankOptions{
			Port:        port,
			Concurrency: conc,
			Timeout:     timeout,
			PauseFunc:   h.isPaused,
		}
		progressCb := func(processed, totalIPs, reachable int, currentIP string) {
			if !h.isStopped() {
				l.OnProgress(processed, totalIPs, reachable, totalIPs, currentIP,
					calcETA(start, processed, totalIPs))
			}
		}

		results := scanner.SpeedRankIPs(h.ctx, ips, opts, progressCb)

		// Persist every ranked line to disk, but stream to the live UI only while
		// not stopped — otherwise a stop would keep emitting results/logs.
		stopped := h.isStopped()
		reachable := 0
		for i, r := range results {
			if r.Reachable {
				reachable++
			}
			line := scanner.FormatSpeedRankLine(i+1, r)
			rf.write(line)
			if !stopped && resultThrottle.allow() {
				l.OnResult(line)
			}
		}
		rf.flush()
		if csvPath, err := scanner.WriteSpeedRankCSV(dataDir, results); err == nil && !stopped {
			l.OnLog("[SPEEDRANK] Ranked CSV saved to " + csvPath)
		}
		if !stopped {
			l.OnLog(fmt.Sprintf("[SPEEDRANK] Done: %d reachable / %d total", reachable, total))
		}

		// A stop is not an error: every ranked line was already written to disk
		// above, so return the saved path so the user keeps their partial results.
		l.OnDone(rf.close(), "")
	}()
	return h
}

// ── ASN export & search ──────────────────────────────────────────────────────

// ExportASN expands all ASNs matching query into a flat IP list on disk under
// {dataDir}/asn_exports/. Returns the output file path.
func ExportASN(dataDir, query string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	groups, err := eng.SearchGroups(query)
	if err != nil {
		return "", err
	}
	if len(groups) == 0 {
		return "", fmt.Errorf("no ASNs matched %q", query)
	}
	cidrs := make([]string, 0)
	for _, g := range groups {
		cidrs = append(cidrs, g.CIDRs...)
	}
	path, _, err := asnexport.ExportTargetsToTXT(dataDir, cidrs, "")
	return path, err
}

// ExpandASNs takes newline/space/comma-separated ASN identifiers (e.g. the ones
// the ASN picker returns) and expands each to its IPv4 CIDRs, returning them as
// a newline-separated string suitable for use as scan Targets. IPv6 ranges are
// skipped because the IP/SNI/proxy scanners operate on IPv4.
func ExpandASNs(dataDir, asnIDs string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.LoadIPv4(); err != nil {
		return "", err
	}
	ids := splitTargets(asnIDs)
	if len(ids) == 0 {
		return "", fmt.Errorf("no ASNs given")
	}
	cidrs, err := eng.IPv4CIDRsForASNs(ids)
	if err != nil {
		return "", err
	}
	if len(cidrs) == 0 {
		return "", fmt.Errorf("no IPv4 CIDRs found for the selected ASN(s)")
	}
	return strings.Join(cidrs, "\n"), nil
}

// ExportCIDRs expands the given newline/space/comma-separated CIDRs into a flat
// IP list written under {dataDir}/asn_exports/ and returns the file path.
func ExportCIDRs(dataDir, cidrs string) (string, error) {
	list := splitTargets(cidrs)
	if len(list) == 0 {
		return "", fmt.Errorf("no CIDRs to export")
	}
	path, _, err := asnexport.ExportTargetsToTXT(dataDir, list, "")
	return path, err
}

// ASNSearch returns matching ASNs as newline-separated "ASN\tName\tipv4Count"
// rows. ASNs with no IPv4 CIDRs are omitted (the scanner is IPv4-only), and the
// count reported is the IPv4 subnet count — so the picker never offers an ASN
// that would fail to expand.
func ASNSearch(dataDir, query string) (string, error) {
	return asnSearchRows(dataDir, query, 0)
}

func asnSearchRows(dataDir, query string, limit int) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.LoadIPv4(); err != nil {
		return "", err
	}
	groups, err := eng.SearchSummaries(query, limit)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&b, "%s\t%s\t%d\n", g.ASN, g.Name, g.SubnetCount)
	}
	return b.String(), nil
}
