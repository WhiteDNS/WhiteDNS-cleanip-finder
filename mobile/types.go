// Package mobile is the gomobile-facing bridge around the white-proxy scanning
// engine. Every exported symbol uses only gomobile-safe types (string, int,
// bool, []byte, error, and bound struct/interface types) so it can be consumed
// from Kotlin/Java after `gomobile bind`.
//
// Discovery is always in-process ("direct"); masscan/nmap preflight is not
// available on Android.
package mobile

// ScanConfig carries all user-tunable scan options as primitives. Targets and
// SNIDomains are newline/space/comma separated strings; Ports is a comma string
// such as "443,2053,8443" or "8000-8100".
type ScanConfig struct {
	Targets       string // IPs/CIDRs, newline/space separated
	Ports         string // comma/range string; empty -> sane defaults
	Concurrency   int    // worker count; <=0 -> default
	TimeoutMs     int    // per-probe timeout in ms; <=0 -> default
	TransferModel string // proxy scans: "old" or "brrr"
	LowBandwidth  bool   // extend timeouts for slow links
	SNIDomains    string // SNI scan: custom domains; empty -> managed defaults
	SNIStrict     bool   // SNI scan: require SNI itself to be accepted
}

// NewScanConfig returns an empty config (convenient constructor for gomobile,
// which cannot allocate Go structs with field literals from Kotlin).
func NewScanConfig() *ScanConfig { return &ScanConfig{} }
