package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHTTPScanTimeout   = 8 * time.Second
	defaultSOCKS5ScanTimeout = 5 * time.Second
)

// Default and extended port lists must match Python scanner.py exactly
var defaultHTTPProxyPorts = []int{80, 8080, 3128, 8000, 8888, 8118, 8081, 8123}
var extendedHTTPProxyPorts = []int{80, 443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123, 8443, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091, 9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808}
var defaultSOCKS5ProxyPorts = []int{1080, 1081, 1082, 1083, 1085, 3128, 8080, 8118, 9050, 9051, 10808}

const (
	httpWave1Timeout     = 2 * time.Second
	httpWave2Timeout     = 4 * time.Second
	httpWave3Timeout     = 8 * time.Second
	httpWave3Limit       = 8192
	httpWave1Concurrency = 4000
	httpWave2Concurrency = 1000
	httpWave3Concurrency = 200
)

var (
	httpStatusPrefix11 = []byte("HTTP/1.1 200")
	httpStatusPrefix10 = []byte("HTTP/1.0 200")
	exampleDomainSig   = []byte("Example Domain")
)

// ProxyScanOptions controls discovery and verification of HTTP/SOCKS5 proxies.
type ProxyScanOptions struct {
	Ports       []int
	Discovery   string
	Concurrency int
	Timeout     time.Duration
}

type ProxyScanResult struct {
	Protocol     string
	Endpoint     string
	Latency      time.Duration
	DownloadKBps float64
	UploadKBps   float64
	Tags         []string
}

type proxyVerifier interface {
	verify(endpoint string, timeout time.Duration) bool
	defaultPorts() []int
	defaultTimeout() time.Duration
}

type httpVerifier struct{}

func (httpVerifier) defaultPorts() []int           { return defaultHTTPProxyPorts }
func (httpVerifier) defaultTimeout() time.Duration { return defaultHTTPScanTimeout }

type socks5Verifier struct{}

func (socks5Verifier) defaultPorts() []int           { return defaultSOCKS5ProxyPorts }
func (socks5Verifier) defaultTimeout() time.Duration { return defaultSOCKS5ScanTimeout }

// ScanHTTPProxies discovers and verifies HTTP proxies without touching routing state.
func (s *Scanner) ScanHTTPProxies(rawTargets []string, opts ProxyScanOptions) ([]string, error) {
	results, err := s.scanProxies(rawTargets, opts, httpVerifier{})
	return formatProxyScanResults(results), err
}

// ScanSOCKS5Proxies discovers and verifies SOCKS5 proxies without touching routing state.
func (s *Scanner) ScanSOCKS5Proxies(rawTargets []string, opts ProxyScanOptions) ([]string, error) {
	results, err := s.scanProxies(rawTargets, opts, socks5Verifier{})
	return formatProxyScanResults(results), err
}

func (s *Scanner) scanProxies(rawTargets []string, opts ProxyScanOptions, verifier proxyVerifier) ([]ProxyScanResult, error) {
	if len(rawTargets) == 0 {
		return []ProxyScanResult{}, nil
	}

	ports := append([]int(nil), opts.Ports...)
	if len(ports) == 0 {
		ports = verifier.defaultPorts()
	}

	discovery := strings.ToLower(strings.TrimSpace(opts.Discovery))
	if discovery == "" {
		discovery = "masscan"
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 500
	}
	if concurrency > 10000 {
		concurrency = 10000
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = verifier.defaultTimeout()
	}
	s.ensureTransportHealthy(context.Background(), "proxy-scan", nil, timeout, 1)
	stopHealthMonitor := s.startTransportHealthMonitor(context.Background(), "proxy-scan", nil, timeout, 1)
	defer stopHealthMonitor()

	// Log AFTER all variables are defined
	s.logf("[TRACE] scanProxies: targets=%d discovery=%s ports=%v concurrency=%d timeout=%s\n", len(rawTargets), discovery, ports, concurrency, timeout.String())

	s.logf("[TRACE] scanProxies: about to call collectProxyCandidates\n")
	candidates, err := s.collectProxyCandidates(rawTargets, ports, discovery)
	s.logf("[TRACE] scanProxies: collectProxyCandidates returned candidates=%d err=%v\n", len(candidates), err)
	if err != nil {
		s.logf("[ERROR] collectProxyCandidates failed: %v\n", err)
		return nil, err
	}
	if len(candidates) == 0 {
		s.logf("[TRACE] scanProxies: no candidates, returning empty\n")
		return []ProxyScanResult{}, nil
	}
	if _, isHTTP := verifier.(httpVerifier); isHTTP {
		s.logf("[TRACE] scanProxies: shuffling HTTP candidates\n")
		rand.Shuffle(len(candidates), func(i, j int) {
			candidates[i], candidates[j] = candidates[j], candidates[i]
		})
	}

	s.logf("[TRACE] scanProxies: about to call scanProxyCandidates with %d candidates\n", len(candidates))
	verified := s.scanProxyCandidates(candidates, concurrency, timeout, verifier)
	s.logf("[TRACE] scanProxies: scanProxyCandidates returned %d verified\n", len(verified))
	return deduplicateProxyResults(verified), nil
}

func (s *Scanner) collectProxyCandidates(rawTargets []string, ports []int, discovery string) ([]string, error) {
	s.logf("[DEBUG] collectProxyCandidates: discovery=%s targets=%d ports=%d\n", discovery, len(rawTargets), len(ports))
	switch discovery {
	case "direct":
		s.logf("[DEBUG] using direct method (no external tool)\n")
		ranges := ParseIPRanges(rawTargets)
		s.logf("[DEBUG] parsed %d IP ranges\n", len(ranges))
		if len(ranges) == 0 {
			return []string{}, nil
		}

		var candidates []string
		for _, r := range ranges {
			start := ipToInt(r.Start)
			end := ipToInt(r.End)
			for current := start; current <= end; current++ {
				ip := intToIP(current).String()
				shuffledPorts := append([]int(nil), ports...)
				if len(shuffledPorts) > 1 {
					rand.Shuffle(len(shuffledPorts), func(i, j int) {
						shuffledPorts[i], shuffledPorts[j] = shuffledPorts[j], shuffledPorts[i]
					})
				}
				for _, port := range shuffledPorts {
					candidates = append(candidates, fmt.Sprintf("%s:%d", ip, port))
				}
			}
		}
		s.logf("[DEBUG] direct method generated %d candidates\n", len(candidates))
		return deduplicateEndpoints(candidates), nil
	case "nmap":
		s.logf("[DEBUG] using nmap discovery\n")
		return s.withTargetPorts(ports, func() ([]string, error) {
			endpoints, err := s.NmapPreflight(rawTargets, false)
			s.logf("[DEBUG] nmap returned %d endpoints, err=%v\n", len(endpoints), err)
			return endpoints, err
		})
	default:
		s.logf("[DEBUG] using masscan discovery\n")
		return s.withTargetPorts(ports, func() ([]string, error) {
			endpoints, err := s.MasscanPreflight(rawTargets, false)
			s.logf("[DEBUG] masscan returned %d endpoints, err=%v\n", len(endpoints), err)
			return endpoints, err
		})
	}
}

func (s *Scanner) withTargetPorts(ports []int, fn func() ([]string, error)) ([]string, error) {
	if len(ports) == 0 || s == nil || s.config == nil {
		return fn()
	}

	oldPorts := append([]int(nil), s.config.TargetPorts...)
	s.config.TargetPorts = append([]int(nil), ports...)
	defer func() {
		s.config.TargetPorts = oldPorts
	}()

	return fn()
}

func (s *Scanner) scanProxyCandidates(candidates []string, concurrency int, timeout time.Duration, verifier proxyVerifier) []ProxyScanResult {
	total := len(candidates)
	if total == 0 {
		return []ProxyScanResult{}
	}

	// For HTTP proxies, use optimized 3-wave pipeline
	if _, isHTTP := verifier.(httpVerifier); isHTTP {
		s.logf("[TRACE] scanProxyCandidates: Using 3-wave HTTP proxy pipeline for %d candidates\n", total)
		return s.scanProxyCandidatesWave3(candidates, timeout)
	}

	// For SOCKS5, use simple verification
	s.logf("[DEBUG] scanProxyCandidates start (SOCKS5): total=%d concurrency=%d timeout=%s\n", total, concurrency, timeout.String())
	if s.proxyProgressCb != nil {
		s.proxyProgressCb(0, total, 0, "", total)
	}
	if concurrency > total {
		concurrency = total
	}

	var mu sync.Mutex
	var verified []ProxyScanResult
	var completed int64
	var hits int64

	jobs := make(chan string, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for endpoint := range jobs {
				for atomic.LoadInt32(&s.paused) == 1 {
					time.Sleep(100 * time.Millisecond)
				}
				start := time.Now()
				if verifier.verify(endpoint, timeout) {
					result := ProxyScanResult{
						Protocol: proxyProtocolLabel(verifier),
						Endpoint: endpoint,
						Latency:  time.Since(start),
						Tags:     s.profileProxyTags(endpoint, verifier, timeout),
					}
					result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(endpoint, verifier, timeout)
					// Log benchmark results for diagnostics
					if result.DownloadKBps > 0 || result.UploadKBps > 0 {
						s.logf("[DEBUG] transfer benchmark %s down=%.1fKB/s up=%.1fKB/s\n", endpoint, result.DownloadKBps, result.UploadKBps)
					} else {
						s.logf("[DEBUG] transfer benchmark %s returned no throughput\n", endpoint)
					}
					mu.Lock()
					verified = append(verified, result)
					mu.Unlock()
					atomic.AddInt64(&hits, 1)
					s.logf("[+] %s\n", formatProxyResult(result))
				}
				processed := atomic.AddInt64(&completed, 1)
				if processed%50 == 0 || processed == int64(total) {
					s.logf("[*] Verified %d/%d | Found %d\n", processed, total, atomic.LoadInt64(&hits))
					if s.proxyProgressCb != nil {
						s.proxyProgressCb(int(processed), total, int(atomic.LoadInt64(&hits)), "", total)
					}
				}
			}
		}()
	}

	for _, endpoint := range candidates {
		jobs <- endpoint
	}
	close(jobs)
	wg.Wait()
	s.logf("[DEBUG] scanProxyCandidates complete (SOCKS5) processed=%d hits=%d\n", atomic.LoadInt64(&completed), atomic.LoadInt64(&hits))
	return verified
}

// scanProxyCandidatesWave3 implements a per-candidate 3-wave pipeline.
// Each candidate flows W1->W2->W3 independently (like Python), so slow W3
// candidates do not block W1/W2 throughput for the rest of the set.
func (s *Scanner) scanProxyCandidatesWave3(candidates []string, maxTimeout time.Duration) []ProxyScanResult {
	total := len(candidates)
	s.logf("[TRACE] Pipelined Wave3 starting: total=%d candidates (w1=%d w2=%d w3=%d)\n", total, httpWave1Concurrency, httpWave2Concurrency, httpWave3Concurrency)
	_ = maxTimeout

	if total == 0 {
		return []ProxyScanResult{}
	}
	if s.proxyProgressCb != nil {
		s.proxyProgressCb(0, total, 0, "", total)
	}

	minInt := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}

	sem1 := make(chan struct{}, minInt(httpWave1Concurrency, total))
	sem2 := make(chan struct{}, minInt(httpWave2Concurrency, total))
	sem3 := make(chan struct{}, minInt(httpWave3Concurrency, total))

	// Match Python's bounded task-object strategy to avoid goroutine explosion.
	taskCap := httpWave1Concurrency * 4
	if taskCap < 8192 {
		taskCap = 8192
	}
	if taskCap > total {
		taskCap = total
	}
	taskSlots := make(chan struct{}, taskCap)

	var (
		verified []ProxyScanResult
		mu       sync.Mutex
		wg       sync.WaitGroup

		w1Done int64
		w1Pass int64
		w2Done int64
		w2Pass int64
		w3Done int64
		w3Pass int64
	)

	tickEvery := total / 400
	if tickEvery < 1 {
		tickEvery = 1
	}

	report := func(done int64) {
		if done%int64(tickEvery) != 0 && done != int64(total) {
			return
		}
		s.logf("[*] pipeline: w1 %d/%d w2 %d/%d w3 %d/%d found=%d\n",
			atomic.LoadInt64(&w1Pass), atomic.LoadInt64(&w1Done),
			atomic.LoadInt64(&w2Pass), atomic.LoadInt64(&w2Done),
			atomic.LoadInt64(&w3Pass), atomic.LoadInt64(&w3Done),
			int(atomic.LoadInt64(&w3Pass)),
		)
		if s.proxyProgressCb != nil {
			s.proxyProgressCb(int(done), total, int(atomic.LoadInt64(&w3Pass)), "", total)
		}
	}

	for _, endpoint := range candidates {
		taskSlots <- struct{}{}
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			defer func() { <-taskSlots }()
			for atomic.LoadInt32(&s.paused) == 1 {
				time.Sleep(100 * time.Millisecond)
			}
			start := time.Now()

			// Wave 1
			sem1 <- struct{}{}
			ok := httpWave1(ep)
			<-sem1
			done := atomic.AddInt64(&w1Done, 1)
			if ok {
				atomic.AddInt64(&w1Pass, 1)
			} else {
				report(done)
				return
			}

			// Wave 2
			sem2 <- struct{}{}
			ok = httpWave2(ep)
			<-sem2
			atomic.AddInt64(&w2Done, 1)
			if ok {
				atomic.AddInt64(&w2Pass, 1)
			} else {
				report(done)
				return
			}

			// Wave 3 (strict acceptance)
			sem3 <- struct{}{}
			ok = httpWave3(ep)
			<-sem3
			atomic.AddInt64(&w3Done, 1)
			if ok {
				atomic.AddInt64(&w3Pass, 1)
				result := ProxyScanResult{
					Protocol: "http",
					Endpoint: ep,
					Latency:  time.Since(start),
					Tags:     s.profileProxyTags(ep, httpVerifier{}, maxTimeout),
				}
				result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(ep, httpVerifier{}, maxTimeout)
				if result.DownloadKBps > 0 || result.UploadKBps > 0 {
					s.logf("[DEBUG] transfer benchmark %s down=%.1fKB/s up=%.1fKB/s\n", ep, result.DownloadKBps, result.UploadKBps)
				} else {
					s.logf("[DEBUG] transfer benchmark %s returned no throughput\n", ep)
				}
				mu.Lock()
				verified = append(verified, result)
				mu.Unlock()
			}

			report(done)
		}(endpoint)
	}

	wg.Wait()

	if s.proxyProgressCb != nil {
		s.proxyProgressCb(total, total, int(atomic.LoadInt64(&w3Pass)), "", total)
	}
	s.logf("[DEBUG] Pipelined Wave3 complete: final verified=%d\n", len(verified))
	return verified
}

// runProxyWaveOptimized runs an optimized verification wave with proper task distribution
// Uses actual HTTP wave verification functions and higher concurrency for speed
func (s *Scanner) runProxyWaveOptimized(candidates []string, concurrency int, timeout time.Duration, waveName string, isFastPing bool) []ProxyScanResult {
	total := len(candidates)
	if total == 0 {
		return []ProxyScanResult{}
	}
	_ = timeout

	if concurrency > total {
		concurrency = total
	}

	var verified []ProxyScanResult
	var mu sync.Mutex
	var processedCount int64
	var lastReport int64

	// Buffered channel for batch efficiency
	jobs := make(chan string, concurrency)
	var wg sync.WaitGroup

	// Spawn worker goroutines - Go goroutines are very lightweight
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for endpoint := range jobs {
				for atomic.LoadInt32(&s.paused) == 1 {
					time.Sleep(100 * time.Millisecond)
				}
				var passed bool
				start := time.Now()

				// Route to appropriate verification function
				if isFastPing {
					passed = httpWave1(endpoint)
				} else if waveName == "wave2" {
					passed = httpWave2(endpoint)
				} else {
					passed = httpWave3(endpoint)
				}

				if passed {
					result := ProxyScanResult{
						Protocol: "http",
						Endpoint: endpoint,
						Latency:  time.Since(start),
						Tags:     s.profileProxyTags(endpoint, httpVerifier{}, timeout),
					}
					result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(endpoint, httpVerifier{}, timeout)
					mu.Lock()
					verified = append(verified, result)
					mu.Unlock()
				}

				// Progress reporting every 200 or at end
				processed := atomic.AddInt64(&processedCount, 1)
				if processed-lastReport >= 2000 || processed == int64(total) {
					atomic.StoreInt64(&lastReport, processed)
					s.logf("[*] %s: %d/%d processed\n", waveName, processed, total)
				}
			}
		}()
	}

	// Feed jobs to workers
	for _, endpoint := range candidates {
		jobs <- endpoint
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	s.logf("[DEBUG] %s complete: %d/%d verified\n", waveName, len(verified), total)
	return verified
}

func formatProxyScanResults(results []ProxyScanResult) []string {
	if len(results) == 0 {
		return []string{}
	}
	formatted := make([]string, 0, len(results))
	for _, result := range results {
		formatted = append(formatted, formatProxyResult(result))
	}
	return deduplicateEndpoints(formatted)
}

func formatProxyResult(result ProxyScanResult) string {
	protocol := strings.ToLower(strings.TrimSpace(result.Protocol))
	if protocol == "" {
		protocol = "proxy"
	}
	parts := []string{protocol, result.Endpoint}
	if result.Latency > 0 {
		parts = append(parts, fmt.Sprintf("lat=%dms", result.Latency.Milliseconds()))
	}
	if result.DownloadKBps > 0 {
		parts = append(parts, fmt.Sprintf("↓%.1fKB/s", result.DownloadKBps))
	}
	if result.UploadKBps > 0 {
		parts = append(parts, fmt.Sprintf("↑%.1fKB/s", result.UploadKBps))
	}
	for _, tag := range result.Tags {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if tag == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("[%s]", tag))
	}
	return strings.Join(parts, " ")
}

func deduplicateProxyResults(results []ProxyScanResult) []ProxyScanResult {
	if len(results) == 0 {
		return []ProxyScanResult{}
	}
	seen := make(map[string]struct{}, len(results))
	filtered := make([]ProxyScanResult, 0, len(results))
	for _, result := range results {
		line := formatProxyResult(result)
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		filtered = append(filtered, result)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return formatProxyResult(filtered[i]) < formatProxyResult(filtered[j])
	})
	return filtered
}

func proxyProtocolLabel(verifier proxyVerifier) string {
	switch verifier.(type) {
	case httpVerifier:
		return "http"
	case socks5Verifier:
		return "socks5"
	default:
		return "proxy"
	}
}

func (s *Scanner) profileProxyTags(endpoint string, verifier proxyVerifier, timeout time.Duration) []string {
	_ = s
	tagTimeout := timeout / 2
	if tagTimeout <= 0 {
		tagTimeout = 2 * time.Second
	}
	if tagTimeout > 3*time.Second {
		tagTimeout = 3 * time.Second
	}

	var tags []string
	if probeProxyHost(endpoint, verifier, "web.telegram.org", tagTimeout) {
		tags = append(tags, "telegram")
	}
	if probeProxyHost(endpoint, verifier, "chatgpt.com", tagTimeout) {
		tags = append(tags, "chatgpt")
	}
	if probeProxyHost(endpoint, verifier, "psiphon.ca", tagTimeout) {
		tags = append(tags, "psiphon")
	}
	return tags
}

func probeProxyHost(endpoint string, verifier proxyVerifier, host string, timeout time.Duration) bool {
	switch verifier.(type) {
	case httpVerifier:
		return probeHTTPProxyHost(endpoint, host, timeout)
	case socks5Verifier:
		return probeSOCKS5ProxyHost(endpoint, host, timeout)
	default:
		return false
	}
}

func probeHTTPProxyHost(endpoint, host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host, host)
	if _, err := io.WriteString(conn, req); err != nil {
		return false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n <= 0 && err != io.EOF {
		return false
	}
	if n > 0 {
		head := strings.ToLower(string(buf[:n]))
		return strings.Contains(head, "http/") || strings.Contains(head, host)
	}
	return true
}

func probeSOCKS5ProxyHost(endpoint, host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return false
	}

	hostBytes := []byte(host)
	if len(hostBytes) == 0 || len(hostBytes) > 255 {
		return false
	}
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, 0x00, 0x50)
	if _, err := conn.Write(req); err != nil {
		return false
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	if header[1] != 0x00 {
		return false
	}
	switch header[3] {
	case 0x01:
		if _, err := io.CopyN(io.Discard, conn, 6); err != nil {
			return false
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return false
		}
		if _, err := io.CopyN(io.Discard, conn, int64(lenBuf[0])+2); err != nil {
			return false
		}
	case 0x04:
		if _, err := io.CopyN(io.Discard, conn, 18); err != nil {
			return false
		}
	default:
		return false
	}

	reqLine := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host, host)
	if _, err := io.WriteString(conn, reqLine); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n <= 0 && err != io.EOF {
		return false
	}
	if n > 0 {
		head := strings.ToLower(string(buf[:n]))
		return strings.Contains(head, "http/") || strings.Contains(head, host)
	}
	return true
}

func (httpVerifier) verify(endpoint string, timeout time.Duration) bool {
	_ = timeout
	if !httpWave1(endpoint) {
		return false
	}
	if !httpWave2(endpoint) {
		return false
	}
	return httpWave3(endpoint)
}

func httpWave1(endpoint string) bool {
	conn, err := net.DialTimeout("tcp", endpoint, httpWave1Timeout)
	if err != nil {
		return false
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(httpWave1Timeout))
	_ = conn.Close()
	return true
}

func httpWave2(endpoint string) bool {
	conn, err := net.DialTimeout("tcp", endpoint, httpWave2Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(httpWave2Timeout))

	const proxyRequest = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, proxyRequest); err != nil {
		return false
	}

	head := make([]byte, 128)
	n, err := conn.Read(head)
	if n <= 0 || err != nil && err != io.EOF {
		return false
	}
	head = head[:n]
	return bytesHasHTTP200Prefix(head)
}

func httpWave3(endpoint string) bool {
	conn, err := net.DialTimeout("tcp", endpoint, httpWave3Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(httpWave3Timeout))

	const fingerprintRequest = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, fingerprintRequest); err != nil {
		return false
	}

	buf := make([]byte, 0, httpWave3Limit)
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(httpWave3Timeout)
	for len(buf) < cap(buf) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(remaining))
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if bytes.Contains(buf, exampleDomainSig) {
				break
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				break
			}
			return false
		}
	}

	return bytesHasHTTP200Prefix(buf) && bytes.Contains(buf, exampleDomainSig)
}

func bytesHasHTTP200Prefix(data []byte) bool {
	line := bytes.TrimSpace(data)
	return bytes.HasPrefix(line, httpStatusPrefix11) || bytes.HasPrefix(line, httpStatusPrefix10)
}

func (socks5Verifier) verify(endpoint string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return false
	}

	request := []byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50}
	if _, err := conn.Write(request); err != nil {
		return false
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return false
	}

	if _, err := io.WriteString(conn, "HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"); err != nil {
		return false
	}

	probe := make([]byte, 4)
	if _, err := io.ReadFull(conn, probe); err != nil {
		return false
	}
	return strings.HasPrefix(string(probe), "HTTP/")
}
