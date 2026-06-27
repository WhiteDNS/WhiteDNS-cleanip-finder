package tlsprobe

import "time"

// ProbeResult represents a single TLS hostname probe outcome
type ProbeResult struct {
	IP         string  `json:"ip"`
	Hostname   string  `json:"hostname"`
	Port       int     `json:"port"`
	Success    bool    `json:"success"`
	ResultKind string  `json:"result_kind"`
	LatencyMs  float64 `json:"latency_ms"`
	TLSVersion string  `json:"tls_version"`
	// SNIAccepted is true when the TLS handshake presenting the requested SNI
	// succeeded (as opposed to only a no-SNI fallback handshake).
	SNIAccepted bool `json:"sni_accepted"`
	// CertMatchesSNI is true when the presented leaf certificate is valid for the
	// requested hostname (cert SAN/CN covers the SNI). A strong signal for
	// domain-fronting / SNI-spoofing usability.
	CertMatchesSNI bool      `json:"cert_matches_sni"`
	CertCN         string    `json:"cert_cn"`
	CertIssuer     string    `json:"cert_issuer"`
	HTTPStatus     int       `json:"http_status"`
	ServerHeader   string    `json:"server_header"`
	Error          string    `json:"error"`
	ScannedAt      time.Time `json:"scanned_at"`
}
