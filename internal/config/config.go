package config

import (
	"os"
	"strconv"
	"strings"
	"whitedns-go/internal/storage"
)

// MMDFProfile represents a domain fronting profile
type MMDFProfile struct {
	Name        string   // Profile name (e.g., "google", "vercel")
	Domains     []string // Domains routed through this profile
	FrontSNI    string   // SNI to present to edge
	FrontIPHost string   // IP/hostname pair to route through
	ForceALPN   []string // Force ALPN protocols (e.g., ["http/1.1"])
}

// Config mirrors the current Python defaults for proxy host and port.
type Config struct {
	ProxyHost string
	ProxyPort int
	// Persisted scanner toggles
	ProbeRequireHTMLForDomainTokens bool
	ProbeAcceptOnCertMatch          bool
}

// MMDFDomainExcludes lists domains that don't support domain fronting
var MMDFDomainExcludes = map[string]bool{
	"gemini.google.com":      true,
	"bard.google.com":        true,
	"aistudio.google.com":    true,
	"ai.google.dev":          true,
	"notebooklm.google.com":  true,
	"shell.cloud.google.com": true,
}

// MMDFProfiles defines all domain fronting profiles
var MMDFProfiles = []MMDFProfile{
	{
		Name:        "google-video",
		Domains:     []string{"googlevideo.com", "gvt1.com"},
		FrontSNI:    "www.google.com",
		FrontIPHost: "www.google.com",
		ForceALPN:   []string{"http/1.1"},
	},
	{
		Name: "google",
		Domains: []string{
			"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
			"youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com", "ggpht.com",
			"yt.be", "meet.google.com", "turns.goog",
		},
		FrontSNI:    "www.google.com",
		FrontIPHost: "www.google.com",
		ForceALPN:   nil,
	},
	{
		Name: "vercel",
		Domains: []string{
			"vercel.app", "vercel.com", "vercel.dev", "vercel.live", "vercel.sh",
			"vercel-dns.com", "now.sh", "zeit.co", "react.dev", "nextjs.org",
			"cursor.com", "ai-sdk.dev",
		},
		FrontSNI:    "react.dev",
		FrontIPHost: "react.dev",
		ForceALPN:   nil,
	},
	{
		Name: "fastly",
		Domains: []string{
			"fastly.com", "python.org", "pypi.org", "reddit.com",
			"githubusercontent.com", "githubassets.com",
		},
		FrontSNI:    "www.python.org",
		FrontIPHost: "www.python.org",
		ForceALPN:   nil,
	},
	{
		Name:        "cloudfront",
		Domains:     []string{"aws.amazon.com", "letsencrypt.org"},
		FrontSNI:    "kubernetes.io",
		FrontIPHost: "kubernetes.io",
		ForceALPN:   nil,
	},
}

// CloudflareCNAMEDomains for DNS mining of Cloudflare IPs
var CloudflareCNAMEDomains = []string{
	"speed.marisalnc.com", "cloudflare.182682.xyz", "rapid-lake-4bce.zajrvcwp.workers.dev",
	"freeyx.cloudflare88.eu.org", "bestcf.top", "cdn.2020111.xyz", "cfip.cfcdn.vip",
	"cf.0sm.com", "cf.090227.xyz", "cf.zhetengsha.eu.org", "cloudflare.9jy.cc",
	"cf.zerone-cdn.pp.ua", "cfip.1323123.xyz", "cnamefuckxxs.yuchen.icu",
	"cloudflare-ip.mofashi.ltd", "115155.xyz", "cname.xirancdn.us",
	"f3058171cad.002404.xyz", "8.889288.xyz", "cdn.tzpro.xyz", "cf.877771.xyz", "xn--b6gac.eu.org",
}

func Load() Config {
	host := envOrDefault("WHITE_PROXY_HOST", "0.0.0.0")
	port := intEnvOrDefault("WHITE_PROXY_PORT", 8080)

	return Config{
		ProxyHost: host,
		ProxyPort: port,
		// conservative defaults
		ProbeRequireHTMLForDomainTokens: true,
		ProbeAcceptOnCertMatch:          true,
	}
}

// LoadFromFile reads a JSON config file into Config. If the file doesn't
// exist, returns an empty Config and no error.
func LoadFromFile(path string) (Config, error) {
	var cfg Config
	if !storage.FileExists(path) {
		return cfg, nil
	}
	if err := storage.ReadJSON(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// SaveToFile writes the Config to the given path atomically.
func SaveToFile(cfg Config, path string) error {
	return storage.AtomicWriteJSON(path, cfg)
}

func (c Config) ListenAddr() string {
	return c.ProxyHost + ":" + strconv.Itoa(c.ProxyPort)
}

// GetMMDFProfile returns the profile for a domain, or nil if not found.
// Match is suffix-aware so subdomains inherit their parent profile.
func GetMMDFProfile(domain string) *MMDFProfile {
	clean := normalizeMMDFDomain(domain)
	if clean == "" {
		return nil
	}
	for i := range MMDFProfiles {
		for _, candidate := range MMDFProfiles[i].Domains {
			candidate = normalizeMMDFDomain(candidate)
			if candidate == "" {
				continue
			}
			if clean == candidate || strings.HasSuffix(clean, "."+candidate) {
				return &MMDFProfiles[i]
			}
		}
	}
	return nil
}

// IsMMDFExcluded checks if a domain is excluded from fronting.
// Exclusions also match subdomains.
func IsMMDFExcluded(domain string) bool {
	clean := normalizeMMDFDomain(domain)
	if clean == "" {
		return false
	}
	for excluded := range MMDFDomainExcludes {
		excluded = normalizeMMDFDomain(excluded)
		if clean == excluded || strings.HasSuffix(clean, "."+excluded) {
			return true
		}
	}
	return false
}

func normalizeMMDFDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

func envOrDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func intEnvOrDefault(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 65535 {
		return fallback
	}
	return v
}
