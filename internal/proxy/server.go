package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whitedns-go/internal/config"
)

type Server struct {
	Addr string
}

func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen failed on %s: %w", s.Addr, err)
	}
	defer ln.Close()

	log.Printf("[*] WHITEDNS (Go port) listening on %s", s.Addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] accept error: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(60 * time.Second))

	br := bufio.NewReader(client)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	switch first[0] {
	case 0x05:
		s.handleSOCKS5(client, br)
	default:
		s.handleHTTP(client, br)
	}
}

func (s *Server) handleHTTP(client net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	targetHost, targetPort, err := parseHTTPDestination(req)
	if err != nil {
		writeHTTPError(client, http.StatusBadRequest, "bad request")
		return
	}

	if profile := config.GetMMDFProfile(targetHost); profile != nil && !config.IsMMDFExcluded(targetHost) && !strings.EqualFold(req.Method, http.MethodConnect) {
		if upstream, err := s.dialMMDFUpstream(profile); err == nil {
			defer upstream.Close()
			req.RequestURI = ""
			if req.URL != nil {
				req.URL.Scheme = ""
				req.URL.Host = ""
			}
			req.Host = targetHost
			req.Close = true
			if err := req.Write(upstream); err != nil {
				writeHTTPError(client, http.StatusBadGateway, "upstream write failed")
				return
			}
			_, _ = io.Copy(client, upstream)
			return
		}
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), 10*time.Second)
	if err != nil {
		writeHTTPError(client, http.StatusBadGateway, "bad gateway")
		return
	}
	defer upstream.Close()

	if strings.EqualFold(req.Method, http.MethodConnect) {
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		relayBidirectional(client, upstream)
		return
	}

	// Convert proxy-form request to origin-form for the upstream server.
	req.RequestURI = ""
	if req.URL != nil {
		req.URL.Scheme = ""
		req.URL.Host = ""
	}
	req.Close = true
	if err := req.Write(upstream); err != nil {
		writeHTTPError(client, http.StatusBadGateway, "upstream write failed")
		return
	}

	_, _ = io.Copy(client, upstream)
}

func (s *Server) dialMMDFUpstream(profile *config.MMDFProfile) (net.Conn, error) {
	frontHost := profile.FrontIPHost
	if frontHost == "" {
		frontHost = profile.FrontSNI
	}
	if frontHost == "" {
		return nil, errors.New("missing MMDF front host")
	}

	serverName := profile.FrontSNI
	if serverName == "" {
		serverName = frontHost
	}

	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if len(profile.ForceALPN) > 0 {
		tlsCfg.NextProtos = append([]string(nil), profile.ForceALPN...)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(frontHost, "443"), tlsCfg)
}

func (s *Server) handleSOCKS5(client net.Conn, br *bufio.Reader) {
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nMethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, int(nMethods))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// No-auth only for first migration step.
	_, _ = client.Write([]byte{0x05, 0x00})

	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	if head[1] != 0x01 {
		writeSocksReply(client, 0x07)
		return
	}

	host, err := readSocksAddress(br, head[3])
	if err != nil {
		writeSocksReply(client, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		writeSocksReply(client, 0x05)
		return
	}
	defer upstream.Close()

	writeSocksReply(client, 0x00)
	relayBidirectional(client, upstream)
}

func parseHTTPDestination(req *http.Request) (string, int, error) {
	defaultPort := 80
	if strings.EqualFold(req.Method, http.MethodConnect) {
		defaultPort = 443
	}

	hostPort := req.Host
	if hostPort == "" && req.URL != nil {
		hostPort = req.URL.Host
	}
	if hostPort == "" {
		return "", 0, errors.New("missing host")
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			return strings.Trim(hostPort, "[]"), defaultPort, nil
		}
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return strings.Trim(host, "[]"), port, nil
}

func readSocksAddress(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03:
		ln, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, int(ln))
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", errors.New("unsupported atyp")
	}
}

func relayBidirectional(a, b net.Conn) {
	done := make(chan struct{}, 2)

	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}

	go pipe(a, b)
	go pipe(b, a)
	<-done
	<-done
}

func writeSocksReply(client net.Conn, rep byte) {
	// VER, REP, RSV, ATYP(IPv4), BND.ADDR(0.0.0.0), BND.PORT(0)
	_, _ = client.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func writeHTTPError(conn net.Conn, statusCode int, msg string) {
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Error"
	}
	body := msg + "\n"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, len(body), body,
	)
}
