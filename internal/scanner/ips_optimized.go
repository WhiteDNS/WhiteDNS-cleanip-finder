package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// runThreeWavePipelineOptimized uses a worker pool to handle massive scale (millions of IPs)
// without goroutine explosion or memory bloat.
func (s *Scanner) runThreeWavePipelineOptimized(ctx context.Context, endpoints []simpleEndpoint, opts IPScanOptions, progressCb ScanIPsProgressCallback) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	total := len(endpoints)
	if total == 0 {
		return nil
	}

	// Compute unique IP count
	ipSetInit := make(map[string]bool)
	for _, e := range endpoints {
		ipSetInit[e.ip] = true
	}
	totalIPsInit := len(ipSetInit)

	// Send initial progress
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
	if probeOpts.LowBandwidth {
		probeOpts.AdaptiveDomainConcurrency = 1
	} else if probeOpts.AdaptiveDomainConcurrency <= 0 {
		probeOpts.AdaptiveDomainConcurrency = calculateAdaptiveDomainConcurrency(total, 0.0)
	}

	// Set concurrency: respect requested concurrency but avoid
	// spawning more workers than there are jobs or an absolute safety cap.
	capVal := opts.Concurrency
	if capVal <= 0 {
		capVal = 250
	}
	// never create more than 10000 workers as an absolute upper bound
	if capVal > 10000 {
		capVal = 10000
	}
	// don't spawn more workers than endpoints (no point) and cap to 5000
	if capVal > total {
		capVal = total
	}
	if capVal > 5000 {
		capVal = 5000
	}
	throttle := NewAdaptiveThrottle(capVal, 50, 10000, 0.05, s.logf)

	s.logf("[TRACE] runThreeWavePipelineOptimized: starting with endpoints=%d uniqueIPs=%d ports=%d concurrency=%d (worker pool mode)\n",
		total, totalIPsInit, len(opts.Ports), capVal)

	// Create job channel and results channel
	jobs := make(chan simpleEndpoint, capVal*2) // buffer for smooth flow
	resultsChan := make(chan string, 1024)      // small buffer to accumulate results

	var wg sync.WaitGroup
	var processed int32
	var acceptedCount int32
	var skippedCount int32
	var timeoutCount int32
	var rejectCount int32
	var deadCount int32
	useDeadCull := total >= 100
	deadThreshold := 10
	if !useDeadCull {
		deadThreshold = total
	}
	deadIPs := newDeadIPTracker(deadThreshold)
	var lastProgressAt int64 // unix nano

	// Start worker pool
	for w := 0; w < capVal; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return // jobs channel closed
					}
					if useDeadCull && deadIPs.isDead(job.ip) {
						atomic.AddInt32(&skippedCount, 1)
						current := int(atomic.AddInt32(&processed, 1))
						if progressCb != nil {
							progressCb(current, total, int(atomic.LoadInt32(&acceptedCount)), fmt.Sprintf("%s:%d", job.ip, job.port), totalIPsInit)
						}
						continue
					}

					// Check pause flag
					for atomic.LoadInt32(&s.paused) == 1 {
						time.Sleep(100 * time.Millisecond)
					}

					probeStarted := time.Now()
					result := s.probeIP(ctx, job.ip, job.port, probeOpts)
					probeLatency := time.Since(probeStarted)
					if shouldCountAsDeadIP(result) {
						atomic.AddInt32(&timeoutCount, 1)
						deadIPs.recordTimeout(job.ip)
					} else if result != nil && result.Status == "accept" {
						deadIPs.recordSuccess(job.ip)
						atomic.AddInt32(&acceptedCount, 1)
						// Log domain scores for this passing result
						// Prefer listing PassedDomains; if empty but a Domain is present, fall back to that
						var passedDomainsStr string
						if len(result.PassedDomains) > 0 {
							passedDomainsStr = strings.Join(result.PassedDomains, ",")
						} else if result.Domain != "" {
							passedDomainsStr = result.Domain
						} else {
							passedDomainsStr = ""
						}
						s.logf("[ACCEPT] %s:%d status=%s domains=%d/%d domain_score=%d passed=[%s]\n", job.ip, job.port, result.Status, result.DomainsTested, result.DomainTotal, result.DomainScore, passedDomainsStr)
						if !probeOpts.LowBandwidth {
							if downloadKBps, uploadKBps, transferTags := s.benchmarkEndpointTransfer(fmt.Sprintf("%s:%d", job.ip, job.port), job.port == 443 || job.port == 2053 || job.port == 2083 || job.port == 2087 || job.port == 2096 || job.port == 8443, probeOpts.Timeout); downloadKBps > 0 || uploadKBps > 0 || len(transferTags) > 0 {
								parts := []string{"http", fmt.Sprintf("%s:%d", job.ip, job.port), fmt.Sprintf("lat=%dms", probeLatency.Milliseconds())}
								if summary := proxyTransferBenchmarkSummary(downloadKBps, uploadKBps); summary != "" {
									parts = append(parts, summary)
								}
								for _, tag := range transferTags {
									parts = append(parts, fmt.Sprintf("[%s]", tag))
								}
								s.logf("[+] %s\n", strings.Join(parts, " "))
							}
						}
						resultsChan <- fmt.Sprintf("%s:%d", job.ip, job.port)
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

					// Throttle progress callback for massive scans (every 25 probes or about 250ms).
					now := time.Now().UnixNano()
					lastProg := atomic.LoadInt64(&lastProgressAt)
					shouldReport := current >= total ||
						current%25 == 0 ||
						lastProg == 0 ||
						now-lastProg >= 250000000 // 250ms

					if progressCb != nil && shouldReport {
						progressCb(current, total, int(atomic.LoadInt32(&acceptedCount)),
							fmt.Sprintf("%s:%d", job.ip, job.port), totalIPsInit)
						atomic.StoreInt64(&lastProgressAt, now)
					}
				}
			}
		}()
	}

	s.logf("[TRACE] DeadIPCull: dead_ips=%d, threshold=%d\n", deadIPs.deadCount(), deadIPs.threshold)

	// Feed jobs to workers
	go func() {
		for _, e := range endpoints {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- e:
			}
		}
		close(jobs)
	}()

	// Close result channel after all workers finish.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results synchronously to avoid races and dropped accepts.
	resultList := make([]string, 0, 1024)
	for r := range resultsChan {
		resultList = append(resultList, r)
	}

	// Final progress report
	if progressCb != nil {
		progressCb(int(atomic.LoadInt32(&processed)), total, int(atomic.LoadInt32(&acceptedCount)), "", totalIPsInit)
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

	s.logf("[TRACE] runThreeWavePipelineOptimized: complete - processed=%d accepted=%d\n", int(atomic.LoadInt32(&processed)), len(resultList))
	return resultList
}
