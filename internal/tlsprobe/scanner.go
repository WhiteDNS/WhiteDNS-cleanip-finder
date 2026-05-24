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
func ProbeOne(ip, hostname string, port int, timeout time.Duration) ProbeResult {
	r := ProbeResult{IP: ip, Hostname: hostname, Port: port, ScannedAt: time.Now()}
	start := time.Now()

	// allow a couple of small retries for transient network failures
	attempts := 2
	var conn net.Conn
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
		cancel()
		if err == nil {
			break
		}
		// small backoff before retrying
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		r.Error = err.Error()
		r.Success = false
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}

	// ensure close on exit
	defer conn.Close()

	remaining := timeout - time.Since(start)
	if remaining <= 0 {
		r.Error = "timeout before TLS"
		r.Success = false
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}

	// Try handshake with provided SNI, if it fails try one more time without SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(remaining))
	if err := tlsConn.Handshake(); err != nil {
		// try once without ServerName in case the server rejects SNI
		// reopen raw TCP connection for second attempt
		remaining = timeout - time.Since(start)
		if remaining <= 0 {
			r.Error = "timeout before TLS retry"
			r.Success = false
			r.LatencyMs = float64(time.Since(start).Milliseconds())
			return r
		}
		conn2, err2 := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err2 != nil {
			r.Error = err.Error()
			r.Success = false
			r.LatencyMs = float64(time.Since(start).Milliseconds())
			return r
		}
		defer conn2.Close()
		tlsConn2 := tls.Client(conn2, &tls.Config{InsecureSkipVerify: true})
		_ = tlsConn2.SetDeadline(time.Now().Add(remaining))
		if err3 := tlsConn2.Handshake(); err3 != nil {
			r.Error = err3.Error()
			r.Success = false
			r.LatencyMs = float64(time.Since(start).Milliseconds())
			return r
		}
		cs := tlsConn2.ConnectionState()
		r.Success = true
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		r.TLSVersion = tlsVersionString(cs.Version)
		if len(cs.PeerCertificates) > 0 {
			cert := cs.PeerCertificates[0]
			if cert.Subject.CommonName != "" {
				r.CertCN = cert.Subject.CommonName
			}
			if cert.Issuer.CommonName != "" {
				r.CertIssuer = cert.Issuer.CommonName
			} else if len(cert.Issuer.Organization) > 0 {
				r.CertIssuer = strings.Join(cert.Issuer.Organization, ",")
			}
		}
		// probe HTTP over the established TLS connection
		remaining = timeout - time.Since(start)
		if remaining <= 0 {
			r.Error = "timeout before HTTP probe"
			r.Success = false
			r.LatencyMs = float64(time.Since(start).Milliseconds())
			return r
		}
		status, server := probeHTTP(tlsConn2, hostname, remaining)
		r.HTTPStatus = status
		r.ServerHeader = server
		return r
	}

	cs := tlsConn.ConnectionState()
	r.Success = true
	r.LatencyMs = float64(time.Since(start).Milliseconds())
	r.TLSVersion = tlsVersionString(cs.Version)

	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		if cert.Subject.CommonName != "" {
			r.CertCN = cert.Subject.CommonName
		}
		if cert.Issuer.CommonName != "" {
			r.CertIssuer = cert.Issuer.CommonName
		} else if len(cert.Issuer.Organization) > 0 {
			r.CertIssuer = strings.Join(cert.Issuer.Organization, ",")
		}
	}

	// probe HTTP over the established TLS connection
	remaining = timeout - time.Since(start)
	if remaining <= 0 {
		r.Error = "timeout before HTTP probe"
		r.Success = false
		r.LatencyMs = float64(time.Since(start).Milliseconds())
		return r
	}
	status, server := probeHTTP(tlsConn, hostname, remaining)
	r.HTTPStatus = status
	r.ServerHeader = server
	return r
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
	// write request
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return 0, ""
	}

	r := bufio.NewReader(tlsConn)
	// read status line(s) and find a line that starts with HTTP/
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
			// now read headers
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
				if len(kv) == 2 {
					key := strings.TrimSpace(kv[0])
					val := strings.TrimSpace(kv[1])
					if strings.EqualFold(key, "Server") {
						serverHeader = val
					}
				}
			}
			break
		}
	}
	return statusCode, serverHeader
}

// RunScan runs ProbeOne over all (ip x hostname) pairs using a worker pool.
// It expands CIDR ranges (skips ranges > 65536). Sends ProbeResult to
// resultCh and sends +1 to progressCh for each completed probe. Closes
// resultCh and progressCh when done.
func RunScan(cfg ScanConfig, resultCh chan<- ProbeResult, progressCh chan<- int) {
	defer func() {
		if resultCh != nil {
			close(resultCh)
		}
		if progressCh != nil {
			close(progressCh)
		}
	}()

	// defaults
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.TimeoutSec <= 0 {
		// use a slightly higher default for SNI/TLS probing to avoid spurious timeouts
		cfg.TimeoutSec = 8.0
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}

	// expand targets into IP list.
	// Callers must pass open channels; RunScan owns and closes resultCh/progressCh.
	ips := expandTargets(cfg.Targets)
	if len(ips) == 0 {
		return
	}

	// build pairs
	var pairs []struct{ ip, host string }
	for _, ip := range ips {
		for _, h := range cfg.Hostnames {
			pairs = append(pairs, struct{ ip, host string }{ip: ip, host: h})
		}
	}
	if len(pairs) == 0 {
		return
	}

	// worker pool
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	timeout := time.Duration(int64(cfg.TimeoutSec * float64(time.Second)))

	for _, p := range pairs {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := ProbeOne(ip, host, cfg.Port, timeout)
			if resultCh != nil {
				resultCh <- res
			}
			if progressCh != nil {
				progressCh <- 1
			}
		}(p.ip, p.host)
	}

	wg.Wait()
}

// expandTargets expands CIDR ranges and single IPs into a list of IP strings.
// Skips ranges larger than 65536 IPs.
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
			// count addresses in network
			ones, bits := ipnet.Mask.Size()
			count := 1 << (bits - ones)
			if count > 65536 {
				// skip too large
				continue
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
			// iterate only usable hosts: exclude network and broadcast addresses
			firstHost := new(big.Int).Add(startIP, big.NewInt(1))
			lastHost := new(big.Int).Sub(endIP, big.NewInt(1))
			for cur := firstHost; cur.Cmp(lastHost) <= 0; cur.Add(cur, big.NewInt(1)) {
				ipStr := bigIntToIP(cur, ip.To4() == nil)
				if ipStr == "" {
					continue
				}
				if _, ok := seen[ipStr]; !ok {
					seen[ipStr] = struct{}{}
					out = append(out, ipStr)
				}
			}
		} else {
			// single IP
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
	// pad to 16 bytes
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
