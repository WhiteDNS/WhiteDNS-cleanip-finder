package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var defaultProbeDomains = []string{
	"workers.dev",
	"pages.dev",
	"gemini.google.com",
	"notebooklm.google.com",
	"instagram.com",
	"chatgpt.com",
	"web.telegram.org",
	"reddit.com",
	"claude.ai",
}

// probePayloadCache stores pre-built HTTP probe payloads to avoid repeated encoding
var probePayloadCache = sync.Map{}

// globalHTTPClientTimeout starts generous and is adjusted per scan
// Calculated as: max(per-domain timeout) + buffer, matching Python's approach
var globalHTTPClientTimeout = 15 * time.Second

// createHTTPClient builds a reusable HTTP client with configurable timeout
func createHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = globalHTTPClientTimeout
	}
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 512,
			MaxConnsPerHost:     1024,
			DisableKeepAlives:   false,
			DisableCompression:  true,
		},
		Timeout: timeout,
	}
}

// globalHTTPClient reuses connections via pooling instead of creating clients per request
var globalHTTPClient = createHTTPClient(globalHTTPClientTimeout)

// calculateOptimalClientTimeout computes the best client timeout based on scan size.
// Logic: if high endpoint count and expecting mostly W1/early W2 passes, use lower timeout (11s).
// Otherwise, scale up to account for slower responses on large scans (up to 15s matching Python).
func calculateOptimalClientTimeout(endpointCount int) time.Duration {
	switch {
	case endpointCount < 10000:
		// Small scans with fast responses
		return 11 * time.Second
	case endpointCount < 100000:
		// Medium scans with mixed response times
		return 13 * time.Second
	default:
		// Large scans with potentially slow CDN responses (match Python's generous max)
		return 15 * time.Second
	}
}

// domainTokensCache caches pre-computed domain token sets
var domainTokensCache = sync.Map{}

// normalizedDomainCache caches lowercase normalized domains
var normalizedDomainCache = sync.Map{}

// hardRejectPatterns pre-computed for performance
var hardRejectPatterns = []string{
	"error 1034", "error 1001", "error 1002", "error 1003", "error 1016", "error 1033",
	"edge ip restricted", "direct ip access not allowed",
	"peyvandha.ir", "internet.ir", "10.10.3", "cra.ir",
	"app-unavailable-in-region", "unavailable in your region",
	"gemini.google.com/faq",
	"does not have permission to get url", "that's all we know",
	"unknown domain",
	"your client does not have permission", "www.google.com/images/errors/robot.png",
	"invalid host header", "no such application", "fastly error: unknown domain",
}

var softAcceptPatterns = []string{"unable to load site", "sorry, you have been blocked"}

var tlsHTTPFallbackAcceptStatus = map[int]struct{}{
	200: {}, 201: {}, 202: {}, 203: {}, 204: {}, 205: {}, 206: {},
	300: {}, 301: {}, 302: {}, 303: {}, 304: {}, 307: {}, 308: {},
	401: {}, 403: {}, 404: {}, 405: {}, 429: {},
}

// Non-overridable hard reject markers (if present, do not allow TLS->HTTP fallback accept)
var nonOverridableHardReject = []string{
	"error 1034", "error 1001", "error 1002", "error 1003", "error 1016", "error 1033",
	"edge ip restricted", "direct ip access not allowed",
	"peyvandha.ir", "internet.ir", "10.10.3", "cra.ir",
	"app-unavailable-in-region", "unavailable in your region",
	"unknown domain",
	"invalid host header", "no such application", "fastly error: unknown domain",
}

func hasNonOverridableHardReject(respLower string) bool {
	if respLower == "" {
		return false
	}
	for _, p := range nonOverridableHardReject {
		if strings.Contains(respLower, p) {
			return true
		}
	}
	return false
}

func hardRejectTag(respLower string) string {
	if respLower == "" {
		return ""
	}
	if strings.Contains(respLower, "error 1034") || strings.Contains(respLower, "edge ip restricted") {
		return "HARD_REJECT:EDGE_IP_RESTRICTED"
	}
	return ""
}

// probeConcurrencyPerEndpoint is the base per-endpoint domain concurrency (starts at 4, can adapt to 6)
const probeConcurrencyPerEndpoint = 4

// calculateAdaptiveDomainConcurrency determines optimal per-endpoint domain parallelism.
// Logic: start at 4, increase to 6 if:
// - Endpoint count is low (<50k) suggesting bandwidth available
// - Timeout rate is low (<5%) suggesting no resource pressure
// This trades off slight response time gain for more parallelism.
func calculateAdaptiveDomainConcurrency(endpointCount int, timeoutRate float64) int {
	base := 4

	// Only increase concurrency on smaller scans where overhead is lower risk
	if endpointCount < 50000 && timeoutRate < 0.05 {
		return 6
	}

	return base
}

// IPScanResult represents the result of probing an IP
type IPScanResult struct {
	IP            string
	Port          int
	Status        string // "accept", "reject", "soft_accept", "dead"
	Domain        string
	StatusCode    int
	Error         string
	DomainScore   int
	DomainTotal   int
	DomainsTested int
	PassedDomains []string // List of domains this IP:port successfully passed on
}

// IPScanOptions configures IP scanning behavior
type IPScanOptions struct {
	Ports                     []int
	Concurrency               int
	Timeout                   time.Duration
	ProbeDomainsHTTP          []string
	ProbeDomainsHTTPS         []string
	EndpointCount             int
	AdaptiveDomainConcurrency int // Set by pipeline based on scan conditions (default 4, up to 6)
	Method                    string
}

type deadIPState struct {
	timeouts  int
	successes int
}

type deadIPTracker struct {
	mu        sync.Mutex
	threshold int
	state     map[string]deadIPState
}

func newDeadIPTracker(threshold int) *deadIPTracker {
	if threshold < 1 {
		threshold = 1
	}
	return &deadIPTracker{threshold: threshold, state: make(map[string]deadIPState)}
}

func (t *deadIPTracker) isDead(ip string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[ip]
	return s.successes == 0 && s.timeouts >= t.threshold
}

func (t *deadIPTracker) recordTimeout(ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[ip]
	s.timeouts++
	t.state[ip] = s
}

func (t *deadIPTracker) recordSuccess(ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[ip]
	s.successes++
	t.state[ip] = s
}

func (t *deadIPTracker) markDeadNow(ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[ip]
	if s.successes == 0 && s.timeouts < t.threshold {
		s.timeouts = t.threshold
	}
	t.state[ip] = s
}

func (t *deadIPTracker) deadCount() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, s := range t.state {
		if s.successes == 0 && s.timeouts >= t.threshold {
			count++
		}
	}
	return count
}

func shouldCountAsDeadIP(result *IPScanResult) bool {
	if result == nil || result.Status != "dead" {
		return false
	}
	reason := strings.ToLower(result.Error)
	if reason == "" {
		return true
	}
	return strings.Contains(reason, "timeout") ||
		strings.Contains(reason, "i/o timeout") ||
		strings.Contains(reason, "deadline exceeded") ||
		strings.Contains(reason, "no route to host") ||
		strings.Contains(reason, "network is unreachable") ||
		strings.Contains(reason, "host is unreachable")
}

// simpleEndpoint represents a candidate IP:port for pipeline processing
type simpleEndpoint struct {
	ip   string
	port int
}

// ScanIPsProgressCallback is called during scanning to report progress
type ScanIPsProgressCallback func(processed, totalProbes, accepted int, currentIP string, totalIPs int)

const (
	// Default timeouts matching Python
	ScanTimeout       = 6 * time.Second
	HardScanTimeout   = 30 * time.Second
	ProbeReadTimeout  = 3500 * time.Millisecond
	TCPPingTimeout    = 2500 * time.Millisecond
	ProxyCheckTimeout = 6 * time.Second
	BodyVerifyTimeout = 8 * time.Second
)

// Wave timeouts (matching Python defaults)
const (
	W1Timeout = 2 * time.Second
	W2Timeout = 4 * time.Second
	W3Timeout = 8 * time.Second
)

// NewScanner creates a new Scanner instance with configuration
func NewScanner(cfg *ScannerConfig) *Scanner {
	if cfg == nil {
		cfg = &ScannerConfig{
			ProbeTimeout:        ProxyCheckTimeout,
			ProbeRetries:        2,
			MaxConcurrentProbes: 250,
			ProbeIntervalMs:     100,
		}
	}
	s := &Scanner{
		endpoints:   make(map[string]*EndpointStats),
		config:      cfg,
		probeSem:    make(chan struct{}, cfg.MaxConcurrentProbes),
		resultsChan: make(chan ProbeResult, cfg.MaxConcurrentProbes),
		cancelChan:  make(chan struct{}),
	}

	// shared dialer for all probe connections (reduces allocations)
	s.dialer = &net.Dialer{Timeout: 5 * time.Second}

	// TLS session cache to accelerate repeated TLS handshakes during large scans
	s.tlsSessionCache = tls.NewLRUClientSessionCache(4096)

	// scanner-local HTTP client reusing transport and TLS session cache
	transport := &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     1024,
		DisableKeepAlives:   false,
		DisableCompression:  true,
		DialContext:         s.dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ClientSessionCache: s.tlsSessionCache,
		},
	}
	s.httpClient = &http.Client{Transport: transport, Timeout: globalHTTPClientTimeout}

	return s
}

// Pause pauses the scanner's pipeline.
func (s *Scanner) Pause() {
	atomic.StoreInt32(&s.paused, 1)
}

// Resume resumes the scanner's pipeline.
func (s *Scanner) Resume() {
	atomic.StoreInt32(&s.paused, 0)
}

// IsPaused returns true when scanner is paused.
func (s *Scanner) IsPaused() bool {
	return atomic.LoadInt32(&s.paused) == 1
}

// ScanIPsWithCIDR scans IPs from CIDR blocks for connectivity
func (s *Scanner) ScanIPsWithCIDR(cidrs []string, opts IPScanOptions) ([]string, error) {
	if opts.AdaptiveDomainConcurrency <= 0 {
		// Preserve the normal behavior unless the caller intentionally selects a profile.
		opts.AdaptiveDomainConcurrency = calculateAdaptiveDomainConcurrency(len(cidrs), 0.0)
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 250
	}
	if opts.Timeout <= 0 {
		opts.Timeout = ProxyCheckTimeout
	}
	if len(opts.Ports) == 0 {
		opts.Ports = []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	if len(opts.ProbeDomainsHTTPS) == 0 {
		// Critical domains first (higher success rate), then the broader family.
		opts.ProbeDomainsHTTPS = append([]string(nil), defaultProbeDomains...)
	}
	if len(opts.ProbeDomainsHTTP) == 0 {
		// Critical domains first (higher success rate), then the broader family.
		opts.ProbeDomainsHTTP = append([]string(nil), defaultProbeDomains...)
	}
	opts.ProbeDomainsHTTP = normalizeProbeDomains(opts.ProbeDomainsHTTP)
	opts.ProbeDomainsHTTPS = normalizeProbeDomains(opts.ProbeDomainsHTTPS)
	s.ensureTransportHealthy(context.Background(), "ip-scan", nil, opts.Timeout, 1)
	stopHealthMonitor := s.startTransportHealthMonitor(context.Background(), "ip-scan", nil, opts.Timeout, 1)
	defer stopHealthMonitor()

	s.logf("[DEBUG] ScanIPsWithProgress called with %d CIDRs: %v\n", len(cidrs), cidrs)

	var allIPs []string
	ipSet := make(map[string]bool)
	// Design cap: allow large CIDR expansion up to 65,536 IPs per block (matches Python's behavior)
	maxIPsPerCIDR := 65536

	for _, cidr := range cidrs {
		ips, err := expandCIDR(cidr, maxIPsPerCIDR)
		if err != nil {
			s.logf("[DEBUG] expandCIDR error for %s: %v\n", cidr, err)
			continue
		}
		s.logf("[DEBUG] expandCIDR %s -> %d IPs\n", cidr, len(ips))
		for _, ip := range ips {
			if !ipSet[ip] {
				allIPs = append(allIPs, ip)
				ipSet[ip] = true
			}
		}
	}

	if len(allIPs) == 0 {
		s.logf("[ERROR] ScanIPsWithCIDR: no IPs expanded from CIDRs\n")
		return nil, fmt.Errorf("no IPs expanded from CIDRs")
	}

	// Build endpoints and shuffle to avoid deterministic ordering
	endpoints := make([]simpleEndpoint, 0, len(allIPs)*len(opts.Ports))
	for _, ip := range allIPs {
		for _, port := range opts.Ports {
			endpoints = append(endpoints, simpleEndpoint{ip: ip, port: port})
		}
	}
	rand.Shuffle(len(endpoints), func(i, j int) { endpoints[i], endpoints[j] = endpoints[j], endpoints[i] })

	// Run the 3-wave pipeline (TCP ping, proxy-aware head, full-body fingerprint)
	accepted := s.runThreeWavePipeline(context.Background(), endpoints, opts, nil)
	return accepted, nil
}

// ScanIPsWithProgress performs IP scanning with progress reporting
func (s *Scanner) ScanIPsWithProgress(cidrs []string, opts IPScanOptions, progressCb ScanIPsProgressCallback) ([]string, error) {
	s.logf("[TRACE] ScanIPsWithProgress: starting with cidrs=%d\n", len(cidrs))

	if opts.AdaptiveDomainConcurrency <= 0 {
		opts.AdaptiveDomainConcurrency = calculateAdaptiveDomainConcurrency(len(cidrs), 0.0)
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 250
	}
	if opts.Timeout <= 0 {
		opts.Timeout = ProxyCheckTimeout
	}
	if len(opts.Ports) == 0 {
		opts.Ports = []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	if len(opts.ProbeDomainsHTTPS) == 0 {
		opts.ProbeDomainsHTTPS = append([]string(nil), defaultProbeDomains...)
	}
	if len(opts.ProbeDomainsHTTP) == 0 {
		opts.ProbeDomainsHTTP = append([]string(nil), defaultProbeDomains...)
	}
	opts.ProbeDomainsHTTP = normalizeProbeDomains(opts.ProbeDomainsHTTP)
	opts.ProbeDomainsHTTPS = normalizeProbeDomains(opts.ProbeDomainsHTTPS)
	s.ensureTransportHealthy(context.Background(), "ip-scan", nil, opts.Timeout, 1)
	stopHealthMonitor := s.startTransportHealthMonitor(context.Background(), "ip-scan", nil, opts.Timeout, 1)
	defer stopHealthMonitor()

	s.logf("[TRACE] ScanIPsWithProgress: config set - concurrency=%d timeout=%s ports=%v\n", opts.Concurrency, opts.Timeout.String(), opts.Ports)

	var allIPs []string
	ipSet := make(map[string]bool)
	maxIPsPerCIDR := 65536 // Match Python's cap to prevent loading excessive IPs per ASN

	for _, cidr := range cidrs {
		ips, err := expandCIDR(cidr, maxIPsPerCIDR)
		if err != nil {
			s.logf("[DEBUG] expandCIDR error for %s: %v\n", cidr, err)
			continue
		}
		s.logf("[DEBUG] expandCIDR %s -> %d IPs\n", cidr, len(ips))
		for _, ip := range ips {
			if !ipSet[ip] {
				allIPs = append(allIPs, ip)
				ipSet[ip] = true
			}
		}
	}

	if len(allIPs) == 0 {
		s.logf("[ERROR] ScanIPsWithProgress: no IPs expanded from CIDRs\n")
		return nil, fmt.Errorf("no IPs expanded from CIDRs")
	}

	s.logf("[TRACE] ScanIPsWithProgress: total unique IPs after expansion: %d\n", len(allIPs))

	// Build endpoints and shuffle (pre-allocate for performance)
	endpoints := make([]simpleEndpoint, 0, len(allIPs)*len(opts.Ports))
	for _, ip := range allIPs {
		for _, port := range opts.Ports {
			endpoints = append(endpoints, simpleEndpoint{ip: ip, port: port})
		}
	}
	s.logf("[TRACE] ScanIPsWithProgress: total endpoints created: %d\n", len(endpoints))
	rand.Shuffle(len(endpoints), func(i, j int) { endpoints[i], endpoints[j] = endpoints[j], endpoints[i] })

	// Calculate and apply optimal client timeout based on scan size
	// Small scans (<10k endpoints): use 11s (expecting fast responses)
	// Medium scans (10k-100k): use 13s (mixed response times)
	// Large scans (>100k): use 15s (matching Python's generous max for slow CDNs)
	endpointCount := len(endpoints)
	optimalTimeout := calculateOptimalClientTimeout(endpointCount)
	// For very large scans, increase worker concurrency to match Python's
	// aggressive Wave-1 fanout (Python uses W1_CONCURRENCY=2000). A small
	// `opts.Concurrency` (e.g. 250) will bottleneck throughput on large
	// endpoint sets; raise it automatically unless user explicitly set it.
	if endpointCount > 2500 && opts.Concurrency > 0 && opts.Concurrency < 2000 {
		s.logf("[DEBUG] Increasing opts.Concurrency %d -> 2000 for large scan (endpoints=%d)", opts.Concurrency, endpointCount)
		opts.Concurrency = 2000
	} else if endpointCount > 2500 && opts.Concurrency <= 0 {
		// no explicit concurrency provided — adopt 2000 for large scans
		opts.Concurrency = 2000
	}
	// adjust scanner-local http client timeout and transport to use optimal timeout
	transport := &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     1024,
		DisableKeepAlives:   false,
		DisableCompression:  true,
		DialContext:         s.dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ClientSessionCache: s.tlsSessionCache,
		},
	}
	s.httpClient = &http.Client{Transport: transport, Timeout: optimalTimeout}
	s.logf("[DEBUG] ScanIPsWithProgress: adjusted client timeout to %s for %d endpoints\n", optimalTimeout.String(), endpointCount)

	// Run pipeline with progress callback
	// Use optimized worker pool for scans > 2500 endpoints (more efficient than semaphore-based)
	if len(endpoints) > 2500 {
		s.logf("[DEBUG] ScanIPsWithProgress: using optimized worker pool pipeline for %d endpoints\n", len(endpoints))
		accepted := s.runThreeWavePipelineOptimized(context.Background(), endpoints, opts, progressCb)
		s.logf("[TRACE] ScanIPsWithProgress: optimized pipeline complete - accepted=%d\n", len(accepted))
		return accepted, nil
	}
	s.logf("[DEBUG] ScanIPsWithProgress: using standard semaphore pipeline for %d endpoints\n", len(endpoints))
	accepted := s.runThreeWavePipeline(context.Background(), endpoints, opts, progressCb)
	s.logf("[TRACE] ScanIPsWithProgress: standard pipeline complete - accepted=%d\n", len(accepted))
	return accepted, nil
}

// runThreeWavePipeline executes a 3-wave pipeline mirroring the Python logic:
// Wave1 - TCP connect (short timeout), Wave2 - absolute-URI HEAD check, Wave3 - full GET and fingerprint.
// Semaphores are sized from opts.Concurrency to avoid a hard low cap.
func (s *Scanner) runThreeWavePipeline(ctx context.Context, endpoints []simpleEndpoint, opts IPScanOptions, progressCb ScanIPsProgressCallback) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	total := len(endpoints)
	if total == 0 {
		return nil
	}

	// compute unique IP count early so we can report initial progress
	ipSetInit := make(map[string]bool)
	for _, e := range endpoints {
		ipSetInit[e.ip] = true
	}
	totalIPsInit := len(ipSetInit)
	// send initial progress so UI can render totals even if Wave3 hasn't started
	if progressCb != nil {
		progressCb(0, total, 0, "", totalIPsInit)
	}

	probeOpts := opts
	probeOpts.ProbeDomainsHTTP = normalizeProbeDomains(opts.ProbeDomainsHTTP)
	probeOpts.ProbeDomainsHTTPS = normalizeProbeDomains(opts.ProbeDomainsHTTPS)
	if len(probeOpts.ProbeDomainsHTTP) == 0 {
		probeOpts.ProbeDomainsHTTP = append([]string(nil), defaultProbeDomains...)
	}
	if len(probeOpts.ProbeDomainsHTTPS) == 0 {
		probeOpts.ProbeDomainsHTTPS = append([]string(nil), defaultProbeDomains...)
	}

	capVal := opts.Concurrency
	if capVal <= 0 {
		capVal = 250
	}
	throttle := NewAdaptiveThrottle(capVal, 50, 10000, 0.05, s.logf)

	// Calculate adaptive per-endpoint domain concurrency based on scan size.
	initialDomainConcurrency := probeOpts.AdaptiveDomainConcurrency
	if initialDomainConcurrency <= 0 {
		initialDomainConcurrency = calculateAdaptiveDomainConcurrency(total, 0.0)
	}
	probeOpts.AdaptiveDomainConcurrency = initialDomainConcurrency
	s.logf("[DEBUG] Adaptive domain concurrency initialized to %d for %d endpoints\n", initialDomainConcurrency, total)

	sem := make(chan struct{}, capVal)
	results := make(chan string, total)

	var wg sync.WaitGroup
	var processed int32
	var acceptedCount int32
	var skippedCount int32
	var timeoutCount int32
	var rejectCount int32
	var deadCount int32
	useDeadCull := len(endpoints) >= 100
	deadThreshold := 10
	if !useDeadCull {
		deadThreshold = len(endpoints)
	}
	deadIPs := newDeadIPTracker(deadThreshold)
	var lastProgressAt int64             // unix nano for throttling
	var lastDomainConcurrencyCheck int64 // unix nano for checking domain concurrency adjustment

	// Reuse previously computed IP set
	totalIPs := totalIPsInit
	s.logf("[TRACE] runThreeWavePipeline: starting with endpoints=%d uniqueIPs=%d ports=%d concurrency=%d timeout=%s\n", total, totalIPs, len(opts.Ports), opts.Concurrency, opts.Timeout.String())

	if progressCb != nil {
		progressCb(0, total, 0, "", totalIPs)
	}

	for _, e := range endpoints {
		wg.Add(1)
		go func(ip string, port int) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if useDeadCull && deadIPs.isDead(ip) {
				s.logf("[SKIP] IP %s marked dead, skipping port %d\n", ip, port)
				atomic.AddInt32(&skippedCount, 1)
				current := int(atomic.AddInt32(&processed, 1))
				if progressCb != nil {
					progressCb(current, total, int(atomic.LoadInt32(&acceptedCount)), fmt.Sprintf("%s:%d", ip, port), totalIPs)
				}
				return
			}

			for atomic.LoadInt32(&s.paused) == 1 {
				time.Sleep(100 * time.Millisecond)
			}

			probeStarted := time.Now()
			sem <- struct{}{}
			result := s.probeIP(ctx, ip, port, probeOpts)
			<-sem
			probeLatency := time.Since(probeStarted)
			if shouldCountAsDeadIP(result) {
				s.logf("[TIMEOUT] %s:%d timeout - dead state recorded\n", ip, port)
				atomic.AddInt32(&timeoutCount, 1)
				deadIPs.recordTimeout(ip)
			} else if result != nil && result.Status == "accept" {
				deadIPs.recordSuccess(ip)
				atomic.AddInt32(&acceptedCount, 1)
				// Log domain scores for this passing result. Prefer listing PassedDomains;
				// if empty but a Domain is present, fall back to that so output includes the exact name.
				var passedDomainsStr string
				if len(result.PassedDomains) > 0 {
					passedDomainsStr = strings.Join(result.PassedDomains, ",")
				} else if result.Domain != "" {
					passedDomainsStr = result.Domain
				} else {
					passedDomainsStr = ""
				}
				s.logf("[ACCEPT] %s:%d status=%s domains=%d/%d domain_score=%d passed=[%s]\n", ip, port, result.Status, result.DomainsTested, result.DomainTotal, result.DomainScore, passedDomainsStr)
				if downloadKBps, uploadKBps, transferTags := s.benchmarkEndpointTransfer(fmt.Sprintf("%s:%d", ip, port), port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443, probeOpts.Timeout); downloadKBps > 0 || uploadKBps > 0 || len(transferTags) > 0 {
					parts := []string{"http", fmt.Sprintf("%s:%d", ip, port), fmt.Sprintf("lat=%dms", probeLatency.Milliseconds())}
					if summary := proxyTransferBenchmarkSummary(downloadKBps, uploadKBps); summary != "" {
						parts = append(parts, summary)
					}
					for _, tag := range transferTags {
						parts = append(parts, fmt.Sprintf("[%s]", tag))
					}
					s.logf("[+] %s\n", strings.Join(parts, " "))
				}
				results <- fmt.Sprintf("%s:%d", ip, port)
			} else if result != nil && result.Status == "dead" {
				atomic.AddInt32(&deadCount, 1)
			} else if result != nil && result.Status == "reject" {
				atomic.AddInt32(&rejectCount, 1)
			}

			if result != nil {
				if result.Status == "dead" || result.Status == "reject" {
					throttle.RecordTimeout()
				} else {
					throttle.RecordSuccess()
				}
			}

			current := int(atomic.AddInt32(&processed, 1))

			// Throttle progress callback: report every 25 probes or about 250ms.
			now := time.Now().UnixNano()
			lastProg := atomic.LoadInt64(&lastProgressAt)
			shouldReport := current >= total ||
				current%25 == 0 ||
				lastProg == 0 ||
				now-lastProg >= 250000000 // 250ms

			if progressCb != nil && shouldReport {
				progressCb(current, total, int(atomic.LoadInt32(&acceptedCount)), fmt.Sprintf("%s:%d", ip, port), totalIPs)
				atomic.StoreInt64(&lastProgressAt, now)
			}

			// Periodically recalculate adaptive domain concurrency based on current timeout rate
			lastDomainConcCheck := atomic.LoadInt64(&lastDomainConcurrencyCheck)
			if lastDomainConcCheck == 0 || now-lastDomainConcCheck >= 5000000000 { // every 5 seconds
				timeoutRate := throttle.GetTimeoutRate()
				newDomainConcurrency := calculateAdaptiveDomainConcurrency(len(endpoints), timeoutRate)
				if newDomainConcurrency != probeOpts.AdaptiveDomainConcurrency {
					oldConcurrency := probeOpts.AdaptiveDomainConcurrency
					probeOpts.AdaptiveDomainConcurrency = newDomainConcurrency
					s.logf("[ADAPTIVE] Domain concurrency: %d → %d (endpoints=%d, timeout_rate=%.1f%%)\n",
						oldConcurrency, newDomainConcurrency, len(endpoints), timeoutRate*100)
				}
				atomic.StoreInt64(&lastDomainConcurrencyCheck, now)
			}
		}(e.ip, e.port)
	}

	s.logf("[TRACE] DeadIPCull: dead_ips=%d, threshold=%d\n", deadIPs.deadCount(), deadIPs.threshold)

	go func() {
		wg.Wait()
		close(results)
	}()

	var accepted []string
	for r := range results {
		accepted = append(accepted, r)
	}

	s.logf("[SUMMARY] IP scan complete: endpoints=%d processed=%d accepted=%d skipped=%d timeouts=%d dead=%d rejected=%d deadCull=%v threshold=%d\n",
		total,
		atomic.LoadInt32(&processed),
		atomic.LoadInt32(&acceptedCount),
		atomic.LoadInt32(&skippedCount),
		atomic.LoadInt32(&timeoutCount),
		atomic.LoadInt32(&deadCount),
		atomic.LoadInt32(&rejectCount),
		useDeadCull,
		deadThreshold,
	)
	s.logf("[TRACE] runThreeWavePipeline: complete - processed=%d accepted=%d\n", total, len(accepted))
	return accepted
}

// expandCIDR expands a CIDR block to individual IPs
func expandCIDR(cidr string, maxIPs int) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip != nil {
			return []string{cidr}, nil
		}
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		if len(ips) >= maxIPs {
			break
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// probeIP tests connectivity to an IP:port combination
func (s *Scanner) probeIP(ctx context.Context, ip string, port int, opts IPScanOptions) *IPScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &IPScanResult{
		IP:   ip,
		Port: port,
	}

	isHTTPS := port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443
	s.logf("[PROBE] Starting %s:%d (https=%v)\n", ip, port, isHTTPS)

	// Burst smoothing: very occasional tiny delay to avoid synchronized bursts.
	// Keep this rare to minimize impact on throughput.
	if rand.Intn(1000) < 10 { // ~1% chance
		time.Sleep(time.Duration(1+rand.Intn(5)) * time.Millisecond)
	}

	if isHTTPS {
		result = s.probeHTTPS(ctx, ip, port, opts)
	} else {
		result = s.probeHTTP(ctx, ip, port, opts)
	}

	if result == nil {
		result = &IPScanResult{IP: ip, Port: port, Status: "dead"}
	}

	s.logf("[PROBE] Complete %s:%d status=%s domains=%d/%d score=%d\n",
		ip, port, result.Status, result.DomainsTested, result.DomainTotal, result.DomainScore)

	return result
}

// probeHTTP sends an HTTP probe to an IP
func (s *Scanner) probeHTTP(ctx context.Context, ip string, port int, opts IPScanOptions) *IPScanResult {
	if ctx == nil {
		ctx = context.Background()
	}

	domains := normalizeProbeDomains(opts.ProbeDomainsHTTP)
	if len(domains) == 0 {
		domains = append([]string(nil), defaultProbeDomains...)
	}
	type domainOutcome struct {
		result   *IPScanResult
		accepted bool
	}

	probeDomain := func(domain string) domainOutcome {
		result := &IPScanResult{IP: ip, Port: port, Domain: domain, DomainTotal: len(domains), DomainsTested: 1}
		attempts := s.retryAttemptsForDomain(domain)
		retrySleep := retrySleepDuration(domain, opts.EndpointCount)

		for attempt := 0; attempt < attempts; attempt++ {
			if ctx.Err() != nil {
				result.Status = "dead"
				result.Error = ctx.Err().Error()
				return domainOutcome{result: result}
			}
			if attempt > 0 {
				time.Sleep(retrySleep)
			}

			attemptTimeout := probeTimeoutForDomain(domain, opts.Timeout, attempt, opts.EndpointCount)
			reqCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			url := fmt.Sprintf("http://%s:%d%s", ip, port, probePathForDomain(domain, attempt))
			req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
			req.Header.Set("Host", domain)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
			req.Header.Set("Accept-Encoding", "identity")
			req.Close = false

			resp, err := s.httpClient.Do(req)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					s.logf("[PROBE-TIMEOUT] %s:%d domain=%s hard-deadline reached (HTTP attempt %d)\n", ip, port, domain, attempt)
					result.Status = "dead"
					result.Error = ctx.Err().Error()
					return domainOutcome{result: result}
				}
				if strings.Contains(err.Error(), "timeout") {
					result.Status = "dead"
				} else {
					result.Status = "reject"
				}
				result.Error = err.Error()
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()

			result.StatusCode = resp.StatusCode
			result.Status = classifyResponse(resp.StatusCode, body, resp.Header, domain)
			if result.Status == "accept" {
				return domainOutcome{result: result, accepted: true}
			}
			// soft_accept continues to next retry (if any) to see if it upgrades to accept
			if result.Status == "soft_accept" && attempt < attempts-1 {
				continue
			}
		}

		if result.Status == "" {
			result.Status = "reject"
		}
		return domainOutcome{result: result}
	}

	// Use adaptive domain concurrency from scan options, fallback to constant
	semSize := opts.AdaptiveDomainConcurrency
	if semSize <= 0 {
		semSize = 4 // default if not set
	}
	if semSize < 1 {
		semSize = 1
	}
	if semSize > len(domains) {
		semSize = len(domains)
	}
	sem := make(chan struct{}, semSize)
	outcomes := make(chan domainOutcome, len(domains))
	var wg sync.WaitGroup

	for _, domain := range domains {
		domain := domain
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes <- probeDomain(domain)
		}()
	}

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	result := &IPScanResult{IP: ip, Port: port, DomainTotal: len(domains), DomainsTested: len(domains), PassedDomains: []string{}}
	domainScore := 0
	var bestResult *IPScanResult
	for outcome := range outcomes {
		if outcome.accepted {
			domainScore++
			if outcome.result != nil {
				result.PassedDomains = append(result.PassedDomains, outcome.result.Domain)
			}
			if bestResult == nil || bestResult.Status != "accept" || outcome.result.Status == "accept" {
				copyResult := *outcome.result
				bestResult = &copyResult
			}
			continue
		}
		if outcome.result != nil && outcome.result.Status != "" && result.Status == "" {
			result.Status = outcome.result.Status
			result.Error = outcome.result.Error
		}
	}

	result.DomainScore = domainScore
	if bestResult != nil {
		acceptThreshold := minimumDomainAcceptScore(len(domains))
		bestResult.DomainScore = domainScore
		bestResult.DomainTotal = len(domains)
		bestResult.DomainsTested = len(domains)
		bestResult.PassedDomains = result.PassedDomains
		if domainScore < acceptThreshold {
			bestResult.Status = "reject"
			if bestResult.Error == "" {
				bestResult.Error = fmt.Sprintf("insufficient domain confirmations: %d/%d", domainScore, acceptThreshold)
			}
			s.logf("[NOISE] %s:%d only %d/%d domains confirmed; rejecting to avoid ISP noise\n", ip, port, domainScore, acceptThreshold)
		}
		s.logf("[SCORE] %s:%d domains %d/%d passed:[%s]\n", ip, port, domainScore, len(domains), strings.Join(result.PassedDomains, ","))
		return bestResult
	}
	if result.Status == "" {
		result.Status = "reject"
	}
	s.logf("[SCORE] %s:%d domains %d/%d passed:[%s]\n", ip, port, domainScore, len(domains), strings.Join(result.PassedDomains, ","))

	return result
}

func minimumDomainAcceptScore(domainCount int) int {
	if domainCount <= 1 {
		return 1
	}
	return 2
}

// buildProbePayload constructs and caches HTTP probe payloads
func buildProbePayload(domain, path string) string {
	cacheKey := domain + ":" + path
	if cached, ok := probePayloadCache.Load(cacheKey); ok {
		return cached.(string)
	}

	if path == "" || path == "/" {
		path = "/"
	}
	payload := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html,application/xhtml+xml,application/json\r\nAccept-Encoding: identity\r\n\r\n", path, domain)
	probePayloadCache.Store(cacheKey, payload)
	return payload
}

// probeHTTPS sends an HTTPS probe with SNI
func (s *Scanner) probeHTTPS(ctx context.Context, ip string, port int, opts IPScanOptions) *IPScanResult {
	if ctx == nil {
		ctx = context.Background()
	}

	domains := normalizeProbeDomains(opts.ProbeDomainsHTTPS)
	if len(domains) == 0 {
		domains = append([]string(nil), defaultProbeDomains...)
	}
	type domainOutcome struct {
		result   *IPScanResult
		accepted bool
	}

	probeDomain := func(domain string) domainOutcome {
		result := &IPScanResult{IP: ip, Port: port, Domain: domain, DomainTotal: len(domains), DomainsTested: 1}
		attempts := s.retryAttemptsForDomain(domain)
		retrySleep := retrySleepDuration(domain, opts.EndpointCount)

		for attempt := 0; attempt < attempts; attempt++ {
			if ctx.Err() != nil {
				result.Status = "dead"
				result.Error = ctx.Err().Error()
				return domainOutcome{result: result}
			}
			if attempt > 0 {
				time.Sleep(retrySleep)
			}

			attemptTimeout := probeTimeoutForDomain(domain, opts.Timeout, attempt, opts.EndpointCount)
			dialer := &net.Dialer{Timeout: attemptTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				if ctx.Err() != nil {
					s.logf("[PROBE-TIMEOUT] %s:%d domain=%s hard-deadline reached at attempt %d\n", ip, port, domain, attempt)
					result.Status = "dead"
					result.Error = ctx.Err().Error()
					return domainOutcome{result: result}
				}
				if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "refused") {
					result.Status = "dead"
				} else {
					result.Status = "reject"
				}
				result.Error = err.Error()
				continue
			}

			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}

			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				ClientSessionCache: s.tlsSessionCache,
			})
			_ = tlsConn.SetDeadline(time.Now().Add(attemptTimeout))

			err = tlsConn.Handshake()
			if err != nil {
				tlsConn.Close()
				if strings.Contains(err.Error(), "timeout") {
					result.Status = "dead"
				} else {
					result.Status = "reject"
				}
				result.Error = err.Error()
				continue
			}

			path := probePathForDomain(domain, attempt)
			req := buildProbePayload(domain, path)
			if _, err := tlsConn.Write([]byte(req)); err != nil {
				tlsConn.Close()
				result.Status = "dead"
				result.Error = err.Error()
				continue
			}

			resp, readErr := readLimitedHTTPResponse(tlsConn, 8192)
			if readErr != nil || len(resp) == 0 {
				tlsConn.Close()
				result.Status = "dead"
				if readErr != nil {
					result.Error = readErr.Error()
				} else {
					result.Error = "dead/empty http response"
				}
				continue
			}

			statusCode, headers, body := parseRawHTTPResponse(resp)
			result.StatusCode = statusCode
			result.Status = classifyResponse(statusCode, body, headers, domain)
			result.Domain = domain
			// Apply Python-like TLS->HTTP fallback: if classification was a hard reject
			// but the status code is in tlsHTTPFallbackAcceptStatus and the response
			// doesn't contain non-overridable hard-reject markers, treat as accept.
			if result.Status == "reject" {
				headersLower := buildHeadersLower(headers)
				respLower := headersLower + "\r\n" + strings.ToLower(string(body))
				if _, ok := tlsHTTPFallbackAcceptStatus[statusCode]; ok && !hasNonOverridableHardReject(respLower) {
					result.Status = "accept"
				}
			}
			tlsConn.Close()
			if result.Status == "accept" {
				return domainOutcome{result: result, accepted: true}
			}
			// soft_accept continues to next retry (if any) to see if it upgrades to accept
			if result.Status == "soft_accept" && attempt < attempts-1 {
				continue
			}
		}

		if result.Status == "" {
			result.Status = "reject"
		}
		return domainOutcome{result: result}
	}

	// Use adaptive domain concurrency from scan options, fallback to constant
	semSize := opts.AdaptiveDomainConcurrency
	if semSize <= 0 {
		semSize = 4 // default if not set
	}
	if semSize < 1 {
		semSize = 1
	}
	if semSize > len(domains) {
		semSize = len(domains)
	}
	sem := make(chan struct{}, semSize)
	outcomes := make(chan domainOutcome, len(domains))
	var wg sync.WaitGroup

	for _, domain := range domains {
		domain := domain
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes <- probeDomain(domain)
		}()
	}

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	result := &IPScanResult{IP: ip, Port: port, DomainTotal: len(domains), DomainsTested: len(domains)}
	domainScore := 0
	var bestResult *IPScanResult
	for outcome := range outcomes {
		if outcome.accepted {
			domainScore++
			if outcome.result != nil && (bestResult == nil || bestResult.Status != "accept" || outcome.result.Status == "accept") {
				copyResult := *outcome.result
				bestResult = &copyResult
			}
			continue
		}
		if outcome.result != nil && outcome.result.Status != "" && result.Status == "" {
			result.Status = outcome.result.Status
			result.Error = outcome.result.Error
		}
	}

	result.DomainScore = domainScore
	if bestResult != nil {
		bestResult.DomainScore = domainScore
		bestResult.DomainTotal = len(domains)
		bestResult.DomainsTested = len(domains)
		s.logf("[SCORE] %s:%d domains %d/%d\n", ip, port, domainScore, len(domains))
		return bestResult
	}
	if result.Status == "" {
		result.Status = "reject"
	}
	s.logf("[SCORE] %s:%d domains %d/%d\n", ip, port, domainScore, len(domains))

	return result
}

// classifyResponse applies response classification logic
func classifyResponse(statusCode int, body []byte, headers http.Header, domain string) string {
	// Build a combined lowercased response fragment (headers + body).
	// Python inspects the raw response for hard/soft patterns before
	// attempting to parse the status line. Mirror that ordering so both
	// classifiers behave identically on malformed or header-only responses.
	bodyLower := strings.ToLower(string(body))
	headersLower := buildHeadersLower(headers)
	respLower := headersLower + "\r\n" + bodyLower

	// Check hard reject patterns first (must return reject even if we
	// couldn't parse a valid HTTP status line).
	for _, pattern := range hardRejectPatterns {
		if strings.Contains(respLower, pattern) {
			return "reject"
		}
	}

	// Check soft accept patterns next
	for _, pattern := range softAcceptPatterns {
		if strings.Contains(respLower, pattern) {
			return "soft_accept"
		}
	}

	// Early exits for invalid status codes (after pattern checks)
	if statusCode == 0 {
		return "dead"
	}
	if statusCode < 100 || statusCode >= 600 {
		return "reject"
	}

	// Check domain tokens (use cache)
	domainFound := false
	for _, tok := range cachedDomainTokens(domain) {
		if strings.Contains(respLower, tok) {
			domainFound = true
			break
		}
	}

	hasCDNSig := hasCDNHeaderSignature(headersLower)
	// Python looks for CRLF+location header; mirror that exact check.
	hasLocationMatch := strings.Contains(headersLower, "\r\nlocation:") && domainFound

	switch {
	case statusCode >= 500:
		return "reject"
	case statusCode == 400, statusCode == 403, statusCode == 409, statusCode == 421, statusCode == 451:
		if domainFound && !hasCDNSig {
			return "accept"
		}
		return "reject"
	case statusCode >= 200 && statusCode < 400:
		if domainFound || hasLocationMatch || hasCDNSig {
			return "accept"
		}
		return "reject"
	case statusCode > 400 && statusCode < 500:
		if domainFound || hasCDNSig {
			return "accept"
		}
		return "reject"
	}

	// Unreachable (all cases covered above), but return reject as fallback
	return "reject"
}

func probeTimeoutForDomain(domain string, base time.Duration, attempt int, endpointCount int) time.Duration {
	d := normalizedDomain(domain)
	critical := d == "workers.dev" || d == "pages.dev"
	var extra time.Duration
	var step time.Duration
	switch {
	case endpointCount >= 1000000:
		if critical {
			extra, step = 1500*time.Millisecond, 750*time.Millisecond
		} else {
			extra, step = 750*time.Millisecond, 500*time.Millisecond
		}
	case endpointCount >= 100000:
		if critical {
			extra, step = 2*time.Second, 1*time.Second
		} else {
			extra, step = 1*time.Second, 750*time.Millisecond
		}
	case endpointCount >= 10000:
		if critical {
			extra, step = 3*time.Second, 1500*time.Millisecond
		} else {
			extra, step = 1500*time.Millisecond, 1*time.Second
		}
	default:
		if critical {
			extra, step = 4*time.Second, 2500*time.Millisecond
		} else {
			extra, step = 3*time.Second, 2*time.Second
		}
	}
	return base + extra + time.Duration(attempt)*step
}

func estimateProbeHardTimeout(base time.Duration, probeDomains []string) time.Duration {
	if base <= 0 {
		base = ProxyCheckTimeout
	}
	probeCount := len(probeDomains)
	if probeCount <= 0 {
		probeCount = len(defaultProbeDomains)
	}
	waves := (probeCount + probeConcurrencyPerEndpoint - 1) / probeConcurrencyPerEndpoint
	if waves < 1 {
		waves = 1
	}
	perRetryWorkerBudget := base + 3*time.Second
	hardTimeout := base*time.Duration(waves) + perRetryWorkerBudget*time.Duration(waves-1) + 2*time.Second
	if hardTimeout < HardScanTimeout {
		return HardScanTimeout
	}
	return hardTimeout
}

func retrySleepDuration(domain string, endpointCount int) time.Duration {
	d := normalizedDomain(domain)
	critical := d == "workers.dev" || d == "pages.dev"
	switch {
	case endpointCount >= 1000000:
		if critical {
			return time.Duration(20+rand.Intn(60)) * time.Millisecond
		}
		return time.Duration(10+rand.Intn(30)) * time.Millisecond
	case endpointCount >= 100000:
		if critical {
			return time.Duration(35+rand.Intn(85)) * time.Millisecond
		}
		return time.Duration(15+rand.Intn(45)) * time.Millisecond
	case endpointCount >= 10000:
		if critical {
			return time.Duration(60+rand.Intn(140)) * time.Millisecond
		}
		return time.Duration(25+rand.Intn(75)) * time.Millisecond
	default:
		if critical {
			return time.Duration(150+rand.Intn(350)) * time.Millisecond
		}
		return time.Duration(50+rand.Intn(150)) * time.Millisecond
	}
}

func normalizeProbeDomains(input []string) []string {
	seen := make(map[string]bool)
	ordered := []string{"workers.dev", "pages.dev"}
	for _, d := range input {
		clean := strings.ToLower(strings.TrimSpace(d))
		if clean == "" {
			continue
		}
		ordered = append(ordered, clean)
	}
	ordered = append(ordered, "gemini.google.com", "notebooklm.google.com")
	out := make([]string, 0, len(ordered))
	for _, d := range ordered {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// normalizedDomain returns cached lowercase domain (for performance)
func normalizedDomain(domain string) string {
	if cached, ok := normalizedDomainCache.Load(domain); ok {
		return cached.(string)
	}
	n := strings.ToLower(strings.TrimSpace(domain))
	normalizedDomainCache.Store(domain, n)
	return n
}

// cachedDomainTokens returns cached domain tokens for classification
func cachedDomainTokens(domain string) []string {
	if cached, ok := domainTokensCache.Load(domain); ok {
		return cached.([]string)
	}
	tokens := domainTokens(domain)
	domainTokensCache.Store(domain, tokens)
	return tokens
}

// retryAttemptsForDomain returns retry attempts for a domain based on scanner config.
func (s *Scanner) retryAttemptsForDomain(domain string) int {
	base := 2
	if s != nil && s.config != nil && s.config.ProbeRetries > 0 {
		base = s.config.ProbeRetries
	}
	d := normalizedDomain(domain)
	// critical domains get +1 (capped), gemini gets -1, others get base
	if d == "workers.dev" || d == "pages.dev" {
		if base+1 > 5 {
			return 5
		}
		return base + 1
	}
	if d == "gemini.google.com" {
		if base-1 < 1 {
			return 1
		}
		return base - 1
	}
	if base < 1 {
		return 1
	}
	return base
}

func probePathForDomain(domain string, attempt int) string {
	d := normalizedDomain(domain)
	if d == "workers.dev" || d == "pages.dev" {
		if attempt >= 1 {
			return "/"
		}
		return "/cdn-cgi/trace"
	}
	return "/"
}

func domainTokens(domain string) []string {
	// Match Python's get_base_domain + _domain_match_tokens logic exactly
	clean := strings.ToLower(strings.TrimSpace(domain))
	if clean == "" {
		return nil
	}

	tokens := []string{clean}

	// Get base domain using Python's exact logic
	baseDomain := getBaseDomain(clean)

	// Only add base domain as separate token if it differs from clean
	// (Python returns full domain for SENSITIVE_DOMAINS, so base == clean in those cases)
	if baseDomain != "" && baseDomain != clean {
		tokens = append(tokens, baseDomain)
	}

	return tokens
}

// getBaseDomain implements Python's get_base_domain logic exactly (domain should be pre-normalized)
func getBaseDomain(domain string) string {
	// SENSITIVE_DOMAINS from Python: google.com, chatgpt.com, openai.com
	sensitiveDomains := map[string]bool{
		"google.com":  true,
		"chatgpt.com": true,
		"openai.com":  true,
	}

	// domain is already normalized (lowercase, trimmed) from caller
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	// Check if second-to-last part is a known co-domain suffix
	codomainSuffixes := map[string]bool{
		"co":  true,
		"com": true,
		"org": true,
		"net": true,
		"edu": true,
		"gov": true,
	}

	var base string
	if codomainSuffixes[parts[len(parts)-2]] && len(parts[len(parts)-1]) == 2 {
		// e.g., example.co.uk → co.uk
		base = strings.Join(parts[len(parts)-3:], ".")
	} else {
		// e.g., example.com → example.com
		base = strings.Join(parts[len(parts)-2:], ".")
	}

	// Return full domain if base is sensitive (matching Python behavior)
	if sensitiveDomains[base] {
		return domain
	}

	return base
}

func buildHeadersLower(headers http.Header) string {
	if headers == nil {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		lk := strings.ToLower(k)
		for _, v := range headers[k] {
			b.WriteString(lk)
			b.WriteString(": ")
			b.WriteString(strings.ToLower(v))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func hasCDNHeaderSignature(headersLower string) bool {
	sigs := []string{
		"server: cloudflare",
		"server: gws",
		"server: sffe",
		"server: varnish",
		"server: bunny",
		"x-fastly-request-id:",
		"cf-ray:",
		"cf-cache-status:",
		"x-served-by:",
		"x-cache:",
	}
	for _, s := range sigs {
		if strings.Contains(headersLower, s) {
			return true
		}
	}
	return false
}

func readLimitedHTTPResponse(conn net.Conn, max int) ([]byte, error) {
	buf := make([]byte, 0, max)
	tmp := make([]byte, 2048)
	for len(buf) < max {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if strings.Contains(strings.ToLower(string(buf)), "\r\n\r\n") && len(buf) >= max/2 {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}

func parseRawHTTPResponse(resp []byte) (int, http.Header, []byte) {
	statusCode := 0
	headers := make(http.Header)
	body := []byte{}

	// Find header/body boundary (single index search instead of multiple splits)
	separator := []byte("\r\n\r\n")
	bodyStart := -1
	for i := 0; i <= len(resp)-len(separator); i++ {
		if bytes.Equal(resp[i:i+len(separator)], separator) {
			bodyStart = i + len(separator)
			break
		}
	}

	headBlock := resp
	if bodyStart > 0 {
		headBlock = resp[:bodyStart-len(separator)]
		body = resp[bodyStart:]
	}

	// Parse status line and headers in one pass
	lines := bytes.SplitN(headBlock, []byte("\r\n"), -1)
	if len(lines) > 0 {
		// Parse status code from first line: "HTTP/1.1 200 OK"
		statusLine := lines[0]
		parts := bytes.SplitN(statusLine, []byte(" "), 3)
		if len(parts) >= 2 {
			fmt.Sscanf(string(parts[1]), "%d", &statusCode)
		}
	}

	// Parse headers
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		kv := bytes.SplitN(line, []byte(":"), 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(string(kv[0]))
		v := strings.TrimSpace(string(kv[1]))
		headers.Add(k, v)
	}
	return statusCode, headers, body
}

// ProbeEndpoint tests an individual endpoint (IP:port) against domains
func (s *Scanner) ProbeEndpoint(ctx context.Context, endpoint string, domains []string) ProbeResult {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return ProbeResult{Success: false, Error: "invalid endpoint format"}
	}

	ip := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)

	if port == 0 {
		return ProbeResult{Success: false, Error: "invalid port"}
	}

	opts := IPScanOptions{
		Ports:             []int{port},
		Timeout:           ProxyCheckTimeout,
		ProbeDomainsHTTP:  domains,
		ProbeDomainsHTTPS: domains,
	}

	start := time.Now()
	result := s.probeIP(ctx, ip, port, opts)
	latency := time.Since(start)

	success := result != nil && result.Status == "accept"
	errStr := ""
	if !success && result != nil {
		errStr = result.Error
	}

	var domainScore, domainTotal, domainsTested int
	if result != nil {
		domainScore = result.DomainScore
		domainTotal = result.DomainTotal
		domainsTested = result.DomainsTested
	}

	return ProbeResult{Success: success, Latency: latency, Error: errStr, DomainScore: domainScore, DomainTotal: domainTotal, DomainsTested: domainsTested}
}

// StatEntry represents statistics for a single endpoint
type StatEntry struct {
	SuccessCount int
	FailCount    int
	AvgLatencyMs float64
}

// GetAllStats returns statistics about current scan state
func (s *Scanner) GetAllStats() map[string]StatEntry {
	return make(map[string]StatEntry)
}

// ClearCache clears any cached scanning data
func (s *Scanner) ClearCache() error {
	return nil
}
