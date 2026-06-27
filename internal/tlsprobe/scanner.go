package tlsprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// ProbeOne performs a TCP+TLS handshake to the specified IP:port using the
// provided ServerName (SNI). It returns a ProbeResult with TLS and HTTP info.
func ProbeOne(ip, hostname string, port int, timeout time.Duration, strict bool) ProbeResult {
	return ProbeOneContext(context.Background(), ip, hostname, port, timeout, strict)
}

// ProbeOneContext is ProbeOne with cancellation support. The timeout is a total
// per-pair budget shared by TCP retries, TLS, and the optional HTTP probe.
func ProbeOneContext(ctx context.Context, ip, hostname string, port int, timeout time.Duration, strict bool) ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	r := ProbeResult{IP: ip, Hostname: hostname, Port: port, ScannedAt: time.Now()}
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := start.Add(timeout)

	conn, err := dialWithRetries(probeCtx, ip, port, deadline, 3)
	if err != nil {
		r.Error = err.Error()
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}
	defer func() { _ = conn.Close() }()

	remaining := time.Until(deadline)
	if remaining <= 0 {
		r.Error = "timeout before TLS"
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(remaining))
	sniErr := tlsConn.Handshake()
	if sniErr == nil {
		r.SNIAccepted = true
		r.Success = true
		cs := tlsConn.ConnectionState()
		recordCertInfo(&r, cs, hostname)
		if r.CertMatchesSNI {
			r.ResultKind = "cert-match"
		} else {
			r.ResultKind = "sni-ok"
		}
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		if rem := time.Until(deadline); rem > 0 {
			r.HTTPStatus, r.ServerHeader = probeHTTP(tlsConn, hostname, rem)
		}
		return r
	}

	if strict {
		r.Success = false
		r.SNIAccepted = false
		r.Error = "sni rejected: " + sniErr.Error()
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}

	remaining = time.Until(deadline)
	if remaining <= 0 {
		r.Error = "timeout before TLS retry"
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}
	conn2, err := dialWithRetries(probeCtx, ip, port, deadline, 1)
	if err != nil {
		r.Error = sniErr.Error() + "; fallback: " + err.Error()
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}
	defer func() { _ = conn2.Close() }()

	tlsConn2 := tls.Client(conn2, &tls.Config{InsecureSkipVerify: true})
	_ = tlsConn2.SetDeadline(time.Now().Add(remaining))
	if err := tlsConn2.Handshake(); err != nil {
		r.Error = err.Error()
		r.ResultKind = "fail"
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}

	r.Success = true
	r.SNIAccepted = false
	r.ResultKind = "tls-only"
	cs := tlsConn2.ConnectionState()
	recordCertInfo(&r, cs, hostname)
	r.LatencyMs = float64(time.Since(start).Milliseconds())
	if rem := time.Until(deadline); rem > 0 {
		r.HTTPStatus, r.ServerHeader = probeHTTP(tlsConn2, hostname, rem)
	}
	return r
}

func dialWithRetries(ctx context.Context, ip string, port int, deadline time.Time, attempts int) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return nil, fmt.Errorf("tcp connect timeout: %w", lastErr)
			}
			return nil, context.DeadlineExceeded
		}

		attemptBudget := remaining
		attemptsLeft := attempts - attempt
		if attemptsLeft > 1 {
			if split := remaining / time.Duration(attemptsLeft); split > 0 && split < attemptBudget {
				attemptBudget = split
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, attemptBudget)
		conn, err := (&net.Dialer{}).DialContext(attemptCtx, "tcp", fmt.Sprintf("%s:%d", ip, port))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err

		backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
		if rem := time.Until(deadline); backoff > rem {
			backoff = rem
		}
		if backoff <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("tcp connect failed: %w", lastErr)
	}
	return nil, fmt.Errorf("tcp connect failed")
}

// recordCertInfo fills cert fields and whether the leaf certificate is valid for
// the requested hostname.
func recordCertInfo(r *ProbeResult, cs tls.ConnectionState, hostname string) {
	r.TLSVersion = tlsVersionString(cs.Version)
	if len(cs.PeerCertificates) == 0 {
		return
	}
	cert := cs.PeerCertificates[0]
	if cert.Subject.CommonName != "" {
		r.CertCN = cert.Subject.CommonName
	}
	if cert.Issuer.CommonName != "" {
		r.CertIssuer = cert.Issuer.CommonName
	} else if len(cert.Issuer.Organization) > 0 {
		r.CertIssuer = strings.Join(cert.Issuer.Organization, ",")
	}
	if hostname != "" && cert.VerifyHostname(hostname) == nil {
		r.CertMatchesSNI = true
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

// probeHTTP writes a minimal GET request over tlsConn and reads the response
// status code and Server header. Returns (0, "") on error.
func probeHTTP(tlsConn *tls.Conn, hostname string, timeout time.Duration) (int, string) {
	if tlsConn == nil {
		return 0, ""
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return 0, ""
	}

	r := bufio.NewReader(tlsConn)
	statusCode := 0
	serverHeader := ""
	for i := 0; i < 4; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HTTP/") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				fmt.Sscanf(parts[1], "%d", &statusCode)
			}
			for {
				hline, err := r.ReadString('\n')
				if err != nil {
					break
				}
				hline = strings.TrimSpace(hline)
				if hline == "" {
					break
				}
				kv := strings.SplitN(hline, ":", 2)
				if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "Server") {
					serverHeader = strings.TrimSpace(kv[1])
				}
			}
			break
		}
	}
	return statusCode, serverHeader
}

func RunScan(cfg ScanConfig, resultCh chan<- ProbeResult, progressCh chan<- int) {
	RunScanContext(context.Background(), cfg, resultCh, progressCh)
}

// RunScanContext runs ProbeOneContext over all (ip x port x hostname) tuples
// using a streaming worker pool. It avoids materializing the full tuple list.
func RunScanContext(ctx context.Context, cfg ScanConfig, resultCh chan<- ProbeResult, progressCh chan<- int) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if resultCh != nil {
			func() {
				defer func() { _ = recover() }()
				close(resultCh)
			}()
		}
		if progressCh != nil {
			func() {
				defer func() { _ = recover() }()
				close(progressCh)
			}()
		}
	}()

	ports := normalizePorts(cfg)
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 8.0
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.Concurrency > 10000 {
		cfg.Concurrency = 10000
	}

	ips := expandTargets(cfg.Targets)
	if len(ips) == 0 || len(cfg.Hostnames) == 0 || len(ports) == 0 {
		return
	}

	type job struct {
		ip   string
		host string
		port int
	}

	jobs := make(chan job, cfg.Concurrency*2)
	var wg sync.WaitGroup
	timeout := time.Duration(int64(cfg.TimeoutSec * float64(time.Second)))

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					if !waitWhilePaused(ctx, cfg.PauseFunc) {
						return
					}
					res := ProbeOneContext(ctx, j.ip, j.host, j.port, timeout, cfg.StrictSNI)
					if resultCh != nil {
						select {
						case resultCh <- res:
						case <-ctx.Done():
							return
						}
					}
					if progressCh != nil {
						select {
						case progressCh <- 1:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

producer:
	for _, ip := range ips {
		for _, port := range ports {
			for _, host := range cfg.Hostnames {
				select {
				case <-ctx.Done():
					break producer
				case jobs <- job{ip: ip, host: host, port: port}:
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
}

func waitWhilePaused(ctx context.Context, pauseFunc func() bool) bool {
	if pauseFunc == nil {
		return true
	}
	for pauseFunc() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	return true
}

func normalizePorts(cfg ScanConfig) []int {
	seen := make(map[int]struct{})
	var out []int
	for _, p := range cfg.Ports {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		p := cfg.Port
		if p <= 0 {
			p = 443
		}
		out = append(out, p)
	}
	return out
}

// maxIPsPerCIDR caps how many addresses a single CIDR contributes. Large blocks
// are capped so large ASN networks are still scanned.
const maxIPsPerCIDR = 65536

// ExpandTargets is the exported form of expandTargets so callers can compute an
// accurate probe total (expanded IPs x hostnames x ports) up front for progress.
func ExpandTargets(raw []string) []string { return expandTargets(raw) }

// expandTargets expands CIDR ranges and single IPs into a list of IP strings.
// CIDRs larger than maxIPsPerCIDR are capped to the first maxIPsPerCIDR hosts.
func expandTargets(raw []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			ip, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			shift := bits - ones
			count := maxIPsPerCIDR + 1
			if shift < 31 {
				count = 1 << shift
			}
			startIP := ipToBigInt(ipnet.IP)
			endIP := ipToBigInt(lastIP(ipnet))
			if count == 1 {
				if ipStr := bigIntToIP(startIP, ip.To4() == nil); ipStr != "" {
					if _, ok := seen[ipStr]; !ok {
						seen[ipStr] = struct{}{}
						out = append(out, ipStr)
					}
				}
				continue
			}
			if count <= 2 {
				for cur := new(big.Int).Set(startIP); cur.Cmp(endIP) <= 0; cur.Add(cur, big.NewInt(1)) {
					ipStr := bigIntToIP(cur, ip.To4() == nil)
					if ipStr == "" {
						continue
					}
					if _, ok := seen[ipStr]; !ok {
						seen[ipStr] = struct{}{}
						out = append(out, ipStr)
					}
				}
				continue
			}
			firstHost := new(big.Int).Add(startIP, big.NewInt(1))
			lastHost := new(big.Int).Sub(endIP, big.NewInt(1))
			added := 0
			for cur := firstHost; cur.Cmp(lastHost) <= 0 && added < maxIPsPerCIDR; cur.Add(cur, big.NewInt(1)) {
				ipStr := bigIntToIP(cur, ip.To4() == nil)
				if ipStr == "" {
					continue
				}
				if _, ok := seen[ipStr]; !ok {
					seen[ipStr] = struct{}{}
					out = append(out, ipStr)
					added++
				}
			}
		} else {
			if net.ParseIP(s) == nil {
				continue
			}
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

func ipToBigInt(ip net.IP) *big.Int {
	b := ip.To16()
	if b == nil {
		return big.NewInt(0)
	}
	return big.NewInt(0).SetBytes(b)
}

func bigIntToIP(i *big.Int, wantIPv6 bool) string {
	if i == nil {
		return ""
	}
	b := i.Bytes()
	if len(b) < 16 {
		pad := make([]byte, 16-len(b))
		b = append(pad, b...)
	}
	ip := net.IP(b)
	if !wantIPv6 {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ip.String()
}

func lastIP(network *net.IPNet) net.IP {
	ip := network.IP
	mask := network.Mask
	ipLen := len(ip)
	last := make(net.IP, ipLen)
	for i := 0; i < ipLen; i++ {
		last[i] = ip[i] | (^mask[i])
	}
	return last
}
