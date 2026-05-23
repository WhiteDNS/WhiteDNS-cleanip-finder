package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTransportHealthSummaryUsesOverride(t *testing.T) {
	oldProbe := transportHealthProbe
	transportHealthProbe = func(ctx context.Context, site string, timeout time.Duration) bool {
		return site != "digikala.com"
	}
	defer func() { transportHealthProbe = oldProbe }()

	s := NewScanner(&ScannerConfig{})
	var logMu sync.Mutex
	var logs []string
	s.SetLogCallback(func(msg string) {
		logMu.Lock()
		logs = append(logs, msg)
		logMu.Unlock()
	})

	summary := s.logTransportHealth(context.Background(), "ip-scan", []string{"snapp.ir", "digikala.com", "divar.ir"}, 200*time.Millisecond)
	if summary.Total != 3 || summary.Reachable != 2 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "[HEALTH] ip-scan transport check") {
		t.Fatalf("expected health log, got: %s", joined)
	}
}

func TestScanIPsWithProgressLocalHTTP(t *testing.T) {
	oldProbe := transportHealthProbe
	transportHealthProbe = func(ctx context.Context, site string, timeout time.Duration) bool { return true }
	defer func() { transportHealthProbe = oldProbe }()

	s := NewScanner(&ScannerConfig{})
	s.httpClient = &http.Client{Transport: probeRoundTripper(func(req *http.Request) (*http.Response, error) {
		host := req.Header.Get("Host")
		if host == "example.com" || host == "gemini.google.com" {
			return newMockProbeResponse(http.StatusOK, "<html><body>Example Domain example.com gemini.google.com</body></html>"), nil
		}
		return newMockProbeResponse(http.StatusServiceUnavailable, "noise"), nil
	}), Timeout: 2 * time.Second}

	result := s.probeIP(context.Background(), "127.0.0.1", 8080, IPScanOptions{
		Timeout:           2 * time.Second,
		ProbeDomainsHTTP:  []string{"example.com", "gemini.google.com"},
		ProbeDomainsHTTPS: []string{"example.com", "gemini.google.com"},
	})
	if result == nil || result.Status != "accept" {
		t.Fatalf("expected accepted probe result, got: %+v", result)
	}
	if result.DomainScore < 2 {
		t.Fatalf("expected multi-domain confirmation, got: %+v", result)
	}
}

func TestScanIPsRejectsSingleNoisyHitAcrossMultipleDomains(t *testing.T) {
	oldProbe := transportHealthProbe
	transportHealthProbe = func(ctx context.Context, site string, timeout time.Duration) bool { return true }
	defer func() { transportHealthProbe = oldProbe }()

	s := NewScanner(&ScannerConfig{})
	s.httpClient = &http.Client{Transport: probeRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Host") == "example.com" {
			return newMockProbeResponse(http.StatusOK, "<html><body>Example Domain example.com</body></html>"), nil
		}
		return newMockProbeResponse(http.StatusServiceUnavailable, "noise"), nil
	}), Timeout: 2 * time.Second}

	result := s.probeIP(context.Background(), "127.0.0.1", 8080, IPScanOptions{
		Timeout:           2 * time.Second,
		ProbeDomainsHTTP:  []string{"example.com", "instagram.com"},
		ProbeDomainsHTTPS: []string{"example.com", "instagram.com"},
	})
	if result == nil || result.Status != "reject" {
		t.Fatalf("expected noisy probe to be rejected, got: %+v", result)
	}
	if result.DomainScore != 1 {
		t.Fatalf("expected a single noisy confirmation, got: %+v", result)
	}
}

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (rt probeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

func newMockProbeResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{},
	}
}

func TestScanHTTPAndSOCKS5ProxiesLocalMocks(t *testing.T) {
	oldProbe := transportHealthProbe
	transportHealthProbe = func(ctx context.Context, site string, timeout time.Duration) bool { return true }
	defer func() { transportHealthProbe = oldProbe }()

	oldBenchmark := proxyTransferBenchmark
	proxyTransferBenchmark = func(endpoint string, verifier proxyVerifier, timeout time.Duration) (float64, float64) {
		return 123.4, 56.7
	}
	defer func() { proxyTransferBenchmark = oldBenchmark }()

	httpProxyAddr, closeHTTPProxy := startHTTPProxyMock(t)
	defer closeHTTPProxy()

	socks5ProxyAddr, closeSOCKS5Proxy := startSOCKS5ProxyMock(t)
	defer closeSOCKS5Proxy()

	s := NewScanner(&ScannerConfig{})

	httpResults, err := s.ScanHTTPProxies([]string{"127.0.0.1/32"}, ProxyScanOptions{Ports: []int{mustAtoi(t, mustPort(t, httpProxyAddr))}, Discovery: "direct", Timeout: 2 * time.Second, Concurrency: 1})
	if err != nil {
		t.Fatalf("ScanHTTPProxies failed: %v", err)
	}
	if len(httpResults) == 0 || !strings.Contains(httpResults[0], "http") || !strings.Contains(httpResults[0], "↓123.4KB/s") {
		t.Fatalf("unexpected HTTP proxy result: %v", httpResults)
	}

	socksResults, err := s.ScanSOCKS5Proxies([]string{"127.0.0.1/32"}, ProxyScanOptions{Ports: []int{mustAtoi(t, mustPort(t, socks5ProxyAddr))}, Discovery: "direct", Timeout: 2 * time.Second, Concurrency: 1})
	if err != nil {
		t.Fatalf("ScanSOCKS5Proxies failed: %v", err)
	}
	if len(socksResults) > 0 && (!strings.Contains(socksResults[0], "socks5") || !strings.Contains(socksResults[0], "↑56.7KB/s")) {
		t.Fatalf("unexpected SOCKS5 proxy result: %v", socksResults)
	}
}

func startHTTPProxyMock(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http proxy: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				continue
			}
			go handleHTTPProxyConn(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

func handleHTTPProxyConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\nConnection: close\r\n\r\n<html><body>Example Domain</body></html>")
}

func startSOCKS5ProxyMock(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5 proxy: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				continue
			}
			go handleSOCKS5ProxyConn(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

func handleSOCKS5ProxyConn(conn net.Conn) {
	defer conn.Close()
	_, _ = conn.Write([]byte{0x05, 0x00})
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\nConnection: close\r\n\r\n<html><body>Example Domain</body></html>")
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func mustPort(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split port: %v", err)
	}
	return port
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("atoi %q: %v", value, err)
	}
	return parsed
}
