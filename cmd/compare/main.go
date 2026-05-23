package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"whitedns-go/internal/scanner"
)

// compare probes a single target and runs both Go and Python classifiers on
// the exact same raw response bytes. Usage:
//
// go run ./cmd/compare --ip <ip> --domain <host> --port <port>

var (
	ipFlag     = flag.String("ip", "", "Target IP to probe")
	domainFlag = flag.String("domain", "", "Host header / domain to probe")
	portFlag   = flag.Int("port", 443, "Target port")
	timeout    = flag.Int("timeout", 5, "Connect/read timeout seconds")
)

func main() {
	flag.Parse()
	if *ipFlag == "" || *domainFlag == "" {
		fmt.Println("Usage: --ip <ip> --domain <host> [--port <port>]")
		os.Exit(1)
	}

	raw, err := probeRaw(*ipFlag, *domainFlag, *portFlag, time.Duration(*timeout)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe failed: %v\n", err)
		os.Exit(2)
	}

	// Run Go classifier
	goResult := scanner.ClassifyRawResponse(raw, *domainFlag)
	fmt.Printf("Go classify: %s\n", goResult)

	// Run Python classifier by invoking a small helper. Pass raw as base64 on stdin
	pyResult, perr := runPythonClassifier(raw, *domainFlag)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "python classifier failed: %v\n", perr)
		os.Exit(3)
	}
	fmt.Printf("Py classify: %s\n", pyResult)

	if goResult != pyResult {
		fmt.Println("--> MISMATCH between Go and Python classifiers")
		os.Exit(4)
	}
	fmt.Println("Results match")
}

func probeRaw(ip, domain string, port int, timeout time.Duration) ([]byte, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	isTLS := port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443
	if isTLS {
		cfg := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Build a simple GET probe
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: compare-tool\r\nAccept: */*\r\nConnection: close\r\n\r\n", domain)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// stop if headers found and we've got a decent chunk
			if len(buf) >= 8192 {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	return buf, nil
}

func runPythonClassifier(raw []byte, domain string) (string, error) {
	// Build a small Python snippet that imports cores.scanner.classify_response
	// and reads base64 from stdin.
	py := `import sys,base64
import os
sys.path.insert(0, os.getcwd())
from cores.scanner import classify_response
raw = base64.b64decode(sys.stdin.read())
print(classify_response(raw, sys.argv[1]))
`

	cmd := exec.Command("python", "-c", py, domain)
	// ensure PYTHONPATH includes repo root
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Clean("."))
	in := base64.StdEncoding.EncodeToString(raw)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	// write stdin
	_, _ = stdin.Write([]byte(in))
	stdin.Close()
	outScanner := bufio.NewScanner(stdout)
	var out string
	if outScanner.Scan() {
		out = outScanner.Text()
	}
	// capture stderr for debugging
	errBuf := make([]byte, 0)
	e := bufio.NewReader(stderr)
	b, _ := e.ReadString('\000')
	if b != "" {
		errBuf = append(errBuf, []byte(b)...)
	}
	if err := cmd.Wait(); err != nil {
		return out, fmt.Errorf("python exit: %v, stderr: %s", err, string(errBuf))
	}
	return out, nil
}
