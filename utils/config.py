import os
import json
import ssl
import re
from utils import paths
from utils import storage
from utils import data_store

# ==========================================
# GENERAL CONFIGURATION
# ==========================================
VERSION = "9.2.0"
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8080

DEFAULT_TARGET_PORTS = [443,2053,2083,2087,2096,8443]
TARGET_PORTS = list(DEFAULT_TARGET_PORTS)
LAST_TARGET_PORTS = list(DEFAULT_TARGET_PORTS)

def _normalize_ports(ports):
    normalized = []
    for p in ports or []:
        try:
            port_int = int(p)
        except (TypeError, ValueError):
            continue
        if port_int < 1 or port_int > 65535:
            continue
        if port_int not in normalized:
            normalized.append(port_int)
    if not normalized:
        normalized = list(DEFAULT_TARGET_PORTS)
    return normalized

def primary_target_port():
    return TARGET_PORTS[0] if TARGET_PORTS else 443

def set_target_ports(ports, persist=False, remember=False):
    """
    Normalizes and applies a new target port list.
    Optionally persists the change to config storage.
    """
    global TARGET_PORTS, LAST_TARGET_PORTS
    TARGET_PORTS = _normalize_ports(ports)
    if remember:
        LAST_TARGET_PORTS = list(TARGET_PORTS)
    if persist:
        save_config()
    return TARGET_PORTS

def is_tls_port(port):
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return False
    return port_int in TARGET_PORTS

CONNECTION_MODE = "white_ip" 
DPI_SNI = "speed.cloudflare.com"
DPI_IP = ""

# Optional global MMDF front override. Empty means use per-domain profiles from
# MMDF_FRONTING_PROFILES.
MMDF_SNI = ""
MMDF_IP = ""

# Evasion: SNI Pool to prevent statistical pattern detection
DPI_SNI_POOL = [
    "speed.cloudflare.com", "www.cloudflare.com", "dash.cloudflare.com",
    "api.cloudflare.com", "blog.cloudflare.com", "community.cloudflare.com",
]

# Dynamically populated at startup with SNIs proven to work for DPI_IP
VALIDATED_SNI_POOL = []

def get_active_dpi_sni():
    import random
    # Only rotate if we have securely validated multiple SNIs for our target IP
    if VALIDATED_SNI_POOL:
        return random.choice(VALIDATED_SNI_POOL)
    return DPI_SNI

# ==========================================
# DPI STRATEGY CONFIGURATION
# ==========================================
DPI_STRATEGIES = ["oob"] # Available: "oob", "bad_csum", "ttl", "syn", "rst", "fin", "classic"
ACTIVE_DPI_STRATEGY = "oob"
DPI_FRAGMENTATION = True
ALWAYS_SHOW_DPI_LOGS = False
DPI_FAILURES = 0 # Tracks consecutive failures for auto-tuning

# Router debug logging (prompted at proxy startup; default off)
ROUTER_DEBUG = False

# ==========================================
# FILE PATHS (CANONICAL: data/, LEGACY-COMPATIBLE)
# ==========================================
HOSTS_FILE = data_store.write_path("white_routes.txt")
FAIL_LOG_FILE = data_store.write_path("failed_routes.txt")
WHITE_IPS_CACHE_FILE = data_store.write_path("white_ips_cache.txt")
SOCKS5_CACHE_FILE = data_store.write_path("socks5_cache.txt")
BANNED_ROUTES_FILE = data_store.write_path("banned_routes.txt")
CONFIG_FILE = data_store.write_path("scanner_config.json")
DESYNC_PAIRS_FILE = data_store.write_path("desync_pairs.json")

# ==========================================
# GLOBAL STATE POOLS & CACHES
# ==========================================
IP_POOL = {}  
IP_POOL_METADATA = {}
DEAD_IP_POOL = {} 
FAILED_DOMAINS = set()
BANNED_ROUTES = {}
EXACT_ROUTES = {}
WILDCARD_ROUTES = {}

# Domain pattern routing policy lists
# - ALWAYS_ROUTE_PATTERNS: force white-IP routing (skip native path)
# - DO_NOT_ROUTE_PATTERNS: force native routing (skip white-IP routing)
# Patterns support exact domains (example.com), glob (*.ir), and regex (re:^.*\.ir$)
ALWAYS_ROUTE_PATTERNS = []
DO_NOT_ROUTE_PATTERNS = []
ROUTE_POLICY_VERSION = 0


def touch_route_policy():
    global ROUTE_POLICY_VERSION
    ROUTE_POLICY_VERSION += 1

# Async locks and Semaphores (to be initialized by the proxy core)
_RACE_LOCKS = {}
RACE_SEMAPHORE = None     
_FILE_WRITE_LOCK = None   
ACTIVE_PROXY_CONNECTIONS = 0
BACKGROUND_SCAN_PAUSE_CONNECTIONS = 6

# ==========================================
# TARGET DOMAINS & LISTS
# ==========================================
DEFAULT_DOMAINS = [
    "instagram.com","chatgpt.com", 
    "web.telegram.org", "reddit.com", "claude.ai",
    "pages.dev", "workers.dev"]

# ==========================================
# MMDF (Man-in-the-Middle + Domain Fronting)
# ==========================================
# Domains routed through the MMDF engine instead of the normal relay path.
# Each profile groups domains that share an edge fleet (Google, Vercel,
# Fastly, AWS CloudFront), so the outbound TLS can be terminated with the
# *real* sibling hostname as SNI ("www.google.com" for Google services,
# "react.dev" for Vercel, etc.). Random / fake SNIs don't work — Google's
# edge will close the connection or refuse to serve the inner Host header.
# Targets that *would* match a profile but don't allow domain fronting and
# would 403 the inner Host header. Checked before any profile match.
MMDF_DOMAIN_EXCLUDES = [
    "gemini.google.com",
    "bard.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "notebooklm.google.com",
    "shell.cloud.google.com",
]

MMDF_FRONTING_PROFILES = [
    # Google video CDN: same front but force HTTP/1.1 — googlevideo backends
    # don't speak h2 reliably under the front. Listed first so it wins the
    # match before the broader Google profile.
    {
        "name": "google-video",
        "domains": [
            "googlevideo.com",
            "gvt1.com",
        ],
        "front_sni": "www.google.com",
        "front_ip_host": "www.google.com",
        "force_alpn": ["http/1.1"],
    },
    # All other Google services share Google's edge IPs and accept
    # www.google.com as SNI.
    {
        "name": "google",
        "domains": [
            "google.com",
            "googleapis.com",
            "googleusercontent.com",
            "gstatic.com",
            "youtube.com",
            "youtu.be",
            "youtube-nocookie.com",
            "ytimg.com",
            "ggpht.com",
            "yt.be",
            "meet.google.com",
            "turns.goog",
        ],
        "front_sni": "www.google.com",
        "front_ip_host": "www.google.com",
        "force_alpn": None,
    },
    {
        "name": "vercel",
        "domains": [
            "vercel.app",
            "vercel.com",
            "vercel.dev",
            "vercel.live",
            "vercel.sh",
            "vercel-dns.com",
            "now.sh",
            "zeit.co",
            "react.dev",
            "nextjs.org",
            "cursor.com",
            "ai-sdk.dev",
        ],
        "front_sni": "react.dev",
        "front_ip_host": "react.dev",
        "force_alpn": None,
    },
    {
        "name": "fastly",
        "domains": [
            "fastly.com",
            "python.org",
            "pypi.org",
            "reddit.com",
            "githubusercontent.com",
            "githubassets.com",
        ],
        "front_sni": "www.python.org",
        "front_ip_host": "www.python.org",
        "force_alpn": None,
    },
    {
        "name": "cloudfront",
        "domains": [
            "aws.amazon.com",
            "letsencrypt.org",
        ],
        "front_sni": "kubernetes.io",
        "front_ip_host": "kubernetes.io",
        "force_alpn": None,
    },
]

CLOUDFLARE_CNAME_DOMAINS = [
    "speed.marisalnc.com", "cloudflare.182682.xyz", "rapid-lake-4bce.zajrvcwp.workers.dev",
    "freeyx.cloudflare88.eu.org", "bestcf.top", "cdn.2020111.xyz", "cfip.cfcdn.vip",
    "cf.0sm.com", "cf.090227.xyz", "cf.zhetengsha.eu.org", "cloudflare.9jy.cc",
    "cf.zerone-cdn.pp.ua", "cfip.1323123.xyz", "cnamefuckxxs.yuchen.icu",
    "cloudflare-ip.mofashi.ltd", "115155.xyz", "cname.xirancdn.us",
    "f3058171cad.002404.xyz", "8.889288.xyz", "cdn.tzpro.xyz", "cf.877771.xyz", "xn--b6gac.eu.org"
]

DESYNC_SNI_LIST = [
    "chatgpt.com", "static.cloudflareinsights.com", "npmjs.com", "sourceforge.net",
    "discord.com", "udemy.com", "fiverr.com", "speed.cloudflare.com", "cloudflare.com",
    "api.discordapp.com", "e7.c.lencr.org", "e8.c.lencr.org", "e9.c.lencr.org",
    "r10.c.lencr.org", "r11.c.lencr.org", "r13.c.lencr.org", "stg-e5.c.lencr.org",
    "stg-e7.c.lencr.org", "stg-e8.c.lencr.org", "stg-ye1.c.lencr.org", "stg-r11.c.lencr.org",
    "stg-ye2.c.lencr.org", "stg-yr2.c.lencr.org", "yr1.c.lencr.org", "ye2.c.lencr.org",
    "security.vercel.com", "vercel.portals.safebase.io", "auth.vercel.com", "stackoverflow.com",
    "hcaptcha.com"
]

# ==========================================
# SCANNER & PROXY LIMITS
# ==========================================
SCAN_TIMEOUT = 6.0
HARD_SCAN_TIMEOUT = 45.0
# Global race timeout for a full resolve() attempt. Must be high enough for
# universal endpoints whose baseline RTT can exceed several seconds.
RACE_TIMEOUT = 8.0
# Hard cap for any single router-side network probe. The router wraps connect,
# TLS, and HTTP verification work in this limit to prevent event-loop hangs.
ROUTE_MAX_RACE_MS = int(RACE_TIMEOUT * 1000.0)
PROBE_READ_TIMEOUT = 3.5
SCAN_RETRY_ATTEMPTS = 2

# Routing race architecture knobs (safe defaults)
RACE_BATCH_PRIMARY = 6
RACE_BATCH_FALLBACK = 4
RACE_BATCH_MIN = 2
RACE_BATCH_LOAD_DOWNSTEP = 1
RACE_NATIVE_HEADSTART_SEC = 0.3
RACE_PER_IP_TIMEOUT = 2.5
# After a hot-cache failure, keep the retry budget short so the caller gets
# a fresh answer instead of waiting for a full cold-start race.
ROUTE_FAST_FALLBACK_TIMEOUT_SEC = 2.25
ROUTE_FAST_FALLBACK_PER_IP_TIMEOUT_SEC = 1.75
# Known-latency endpoints need extra headroom so slow-but-valid universal IPs
# do not get clipped by the strict unknown-endpoint timeout.
ROUTE_KNOWN_LATENCY_HEADROOM_MS = 1500.0

# Adaptive concurrency for the race semaphore. The router-level
# AdaptiveThrottler watches gateway RTT and grows/shrinks the limit
# (AIMD) so we don't flood the home router under sustained load.
RACE_CONCURRENCY_INITIAL = 8
RACE_CONCURRENCY_MAX = 24

# L1 route cache behavior
ROUTE_L1_TTL_SEC = 90.0
ROUTE_L1_NATIVE_TTL_SEC = 45.0
ROUTE_EVICT_FAIL_THRESHOLD = 6

# Endpoint score model (weighted additive)
ROUTE_SCORE_LATENCY_WEIGHT = 1.0
ROUTE_SCORE_FAIL_WEIGHT = 250.0
ROUTE_SCORE_RECENCY_WEIGHT = 3.0
ROUTE_SCORE_RECENCY_CAP_SEC = 120.0
ROUTE_EWMA_ALPHA = 0.35
ROUTE_SCORE_NEUTRAL_LATENCY_MS = 700.0
ROUTE_SCORE_FAIL_CAP = 8
ROUTE_FAIL_WEIGHT_GENERIC = 3.0
ROUTE_FAIL_WEIGHT_TIMEOUT = 8.0
ROUTE_FAIL_WEIGHT_CONNECT_ERROR = 12.0
ROUTE_FAIL_WEIGHT_TLS_ERROR = 5.0
ROUTE_FAIL_WEIGHT_HTTP_REJECT = 4.0
# How long an endpoint stays in quarantine before being re-admitted.
ROUTE_QUARANTINE_TTL_SEC = 60.0
ROUTE_QUARANTINE_SEVERE_BASE_SEC = 300.0
ROUTE_QUARANTINE_CONNECT_BASE_SEC = 600.0
ROUTE_QUARANTINE_TLS_BASE_SEC = 900.0
ROUTE_QUARANTINE_TIMEOUT_BASE_SEC = 600.0
ROUTE_QUARANTINE_BACKOFF_MAX_SEC = 86400.0
ROUTE_QUARANTINE_BACKOFF_CAP = 8
ROUTE_QUARANTINE_SEVERE_THRESHOLD = 1
ROUTE_QUARANTINE_TIMEOUT_THRESHOLD = 3
ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD = ROUTE_QUARANTINE_TIMEOUT_THRESHOLD
ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD = 8
ROUTE_QUARANTINE_TLS_THRESHOLD = 4

# Use-time route hygiene (penalties applied by the proxy when a chosen
# route fails or under-performs at connect / relay time).
ROUTE_CONNECT_FAIL_WEIGHT = 6.0      # heavy enough to push past ROUTE_EVICT_FAIL_THRESHOLD
ROUTE_NO_DATA_FAIL_WEIGHT = 4.0
ROUTE_SLOW_FAIL_WEIGHT    = 2.0
ROUTE_QUARANTINE_CONNECT_THRESHOLD = 4
ROUTE_QUARANTINE_RECOVERY_BATCH = 4

# Relay watchdog: a download that produces no bytes for this long is
# treated as a slow/dead IP, the route is demoted, and the next request
# re-races for a fresh IP.
RELAY_SLOW_TTFB_SEC = 5.0

# Cap how many connect-time retries the proxy performs against fresh
# routes when the first chosen IP fails to connect.
ROUTE_CONNECT_RETRIES = 2

# Upstream connect attempt timeout. Short enough that a dead IP triggers
# the retry before the browser gives up, generous enough to cover slow
# TLS handshakes over a high-latency / lossy uplink (e.g. Iran → CDN).
PROXY_CONNECT_TIMEOUT = 6.0

# Apply an HTTP-level verification step inside the routing race. TLS-only
# verification accepts edge IPs that return 403 / 1034 / "your client does
# not have permission" at HTTP layer; the extra GET catches them before
# they can win the route. Costs ~8 KB per candidate per race (cache miss).
ROUTE_HTTP_VERIFY_RACE = True


MAX_CONCURRENT_SCANS = 1000 
CHUNK_SIZE = 50000

TUNED_MASSCAN_RATE = None
TUNED_NMAP_MIN_RATE = None
TUNED_NMAP_MAX_RATE = None

# ==========================================
# TLS / SSL CONTEXTS
# ==========================================
# Strict TLS Context to prevent generic Edge IPs from polluting the pool
SSL_CONTEXT = ssl.create_default_context()
PROBE_SSL_CONTEXT = ssl.create_default_context()
try:
    PROBE_SSL_CONTEXT.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-GCM-SHA256"
    )
    if hasattr(PROBE_SSL_CONTEXT, "set_ciphersuites"):
        PROBE_SSL_CONTEXT.set_ciphersuites(
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
        )
except Exception:
    pass
try: 
    PROBE_SSL_CONTEXT.set_alpn_protocols(['http/1.1'])
except Exception: 
    pass

# ==========================================
# CONFIGURATION PERSISTENCE
# ==========================================
def load_config():
    global MAX_CONCURRENT_SCANS, TUNED_MASSCAN_RATE, TUNED_NMAP_MIN_RATE, TUNED_NMAP_MAX_RATE
    global CONNECTION_MODE, DPI_SNI, DPI_IP, MMDF_SNI, MMDF_IP
    global DPI_STRATEGIES, ACTIVE_DPI_STRATEGY, DPI_FRAGMENTATION
    global VALIDATED_SNI_POOL, ALWAYS_ROUTE_PATTERNS, DO_NOT_ROUTE_PATTERNS
    global TARGET_PORTS, LAST_TARGET_PORTS, PROBE_READ_TIMEOUT, SCAN_RETRY_ATTEMPTS
    global RACE_BATCH_PRIMARY, RACE_BATCH_FALLBACK, RACE_BATCH_MIN, RACE_BATCH_LOAD_DOWNSTEP
    global RACE_NATIVE_HEADSTART_SEC, RACE_PER_IP_TIMEOUT, ROUTE_KNOWN_LATENCY_HEADROOM_MS
    global ROUTE_MAX_RACE_MS
    global ROUTE_L1_TTL_SEC, ROUTE_L1_NATIVE_TTL_SEC, ROUTE_EVICT_FAIL_THRESHOLD
    global ROUTE_SCORE_LATENCY_WEIGHT, ROUTE_SCORE_FAIL_WEIGHT, ROUTE_SCORE_RECENCY_WEIGHT
    global ROUTE_SCORE_RECENCY_CAP_SEC, ROUTE_EWMA_ALPHA
    global ROUTE_SCORE_NEUTRAL_LATENCY_MS, ROUTE_SCORE_FAIL_CAP
    global ROUTE_FAIL_WEIGHT_GENERIC, ROUTE_FAIL_WEIGHT_TIMEOUT
    global ROUTE_FAIL_WEIGHT_CONNECT_ERROR, ROUTE_FAIL_WEIGHT_TLS_ERROR
    global ROUTE_FAIL_WEIGHT_HTTP_REJECT
    global ROUTE_CONNECT_FAIL_WEIGHT, ROUTE_NO_DATA_FAIL_WEIGHT, ROUTE_SLOW_FAIL_WEIGHT
    global ROUTE_QUARANTINE_CONNECT_THRESHOLD, ROUTE_QUARANTINE_RECOVERY_BATCH
    global ROUTE_QUARANTINE_TTL_SEC, ROUTE_QUARANTINE_TIMEOUT_THRESHOLD, ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD
    global ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD, ROUTE_QUARANTINE_TLS_THRESHOLD
    global MMDF_FRONTING_PROFILES
    
    if os.path.exists(CONFIG_FILE):
        try:
            config = storage.read_json(CONFIG_FILE, default={})
            if isinstance(config, dict):
                MAX_CONCURRENT_SCANS = config.get("MAX_CONCURRENT_SCANS", MAX_CONCURRENT_SCANS)
                TUNED_MASSCAN_RATE = config.get("TUNED_MASSCAN_RATE", TUNED_MASSCAN_RATE)
                TUNED_NMAP_MIN_RATE = config.get("TUNED_NMAP_MIN_RATE", TUNED_NMAP_MIN_RATE)
                TUNED_NMAP_MAX_RATE = config.get("TUNED_NMAP_MAX_RATE", TUNED_NMAP_MAX_RATE)
                CONNECTION_MODE = config.get("CONNECTION_MODE", CONNECTION_MODE)
                DPI_SNI = config.get("DPI_SNI", DPI_SNI)
                DPI_IP = config.get("DPI_IP", DPI_IP)
                MMDF_SNI = str(config.get("MMDF_SNI", MMDF_SNI) or "").strip()
                MMDF_IP = str(config.get("MMDF_IP", MMDF_IP) or "").strip()
                DPI_STRATEGIES = config.get("DPI_STRATEGIES", DPI_STRATEGIES)
                DPI_FRAGMENTATION = config.get("DPI_FRAGMENTATION", DPI_FRAGMENTATION)
                ALWAYS_ROUTE_PATTERNS = config.get("ALWAYS_ROUTE_PATTERNS", ALWAYS_ROUTE_PATTERNS)
                DO_NOT_ROUTE_PATTERNS = config.get("DO_NOT_ROUTE_PATTERNS", DO_NOT_ROUTE_PATTERNS)
                LAST_TARGET_PORTS = _normalize_ports(
                    config.get("LAST_TARGET_PORTS", config.get("TARGET_PORTS", LAST_TARGET_PORTS))
                )
                TARGET_PORTS = _normalize_ports(config.get("TARGET_PORTS", TARGET_PORTS))
                RACE_BATCH_PRIMARY = int(config.get("RACE_BATCH_PRIMARY", RACE_BATCH_PRIMARY))
                RACE_BATCH_FALLBACK = int(config.get("RACE_BATCH_FALLBACK", RACE_BATCH_FALLBACK))
                RACE_BATCH_MIN = int(config.get("RACE_BATCH_MIN", RACE_BATCH_MIN))
                RACE_BATCH_LOAD_DOWNSTEP = int(config.get("RACE_BATCH_LOAD_DOWNSTEP", RACE_BATCH_LOAD_DOWNSTEP))
                RACE_NATIVE_HEADSTART_SEC = float(config.get("RACE_NATIVE_HEADSTART_SEC", RACE_NATIVE_HEADSTART_SEC))
                RACE_PER_IP_TIMEOUT = float(config.get("RACE_PER_IP_TIMEOUT", RACE_PER_IP_TIMEOUT))
                ROUTE_MAX_RACE_MS = int(config.get("ROUTE_MAX_RACE_MS", ROUTE_MAX_RACE_MS))
                ROUTE_KNOWN_LATENCY_HEADROOM_MS = float(
                    config.get("ROUTE_KNOWN_LATENCY_HEADROOM_MS", ROUTE_KNOWN_LATENCY_HEADROOM_MS)
                )
                PROBE_READ_TIMEOUT = float(config.get("PROBE_READ_TIMEOUT", PROBE_READ_TIMEOUT))
                SCAN_RETRY_ATTEMPTS = int(config.get("SCAN_RETRY_ATTEMPTS", SCAN_RETRY_ATTEMPTS))

                ROUTE_L1_TTL_SEC = float(config.get("ROUTE_L1_TTL_SEC", ROUTE_L1_TTL_SEC))
                ROUTE_L1_NATIVE_TTL_SEC = float(config.get("ROUTE_L1_NATIVE_TTL_SEC", ROUTE_L1_NATIVE_TTL_SEC))
                ROUTE_EVICT_FAIL_THRESHOLD = int(config.get("ROUTE_EVICT_FAIL_THRESHOLD", ROUTE_EVICT_FAIL_THRESHOLD))

                ROUTE_SCORE_LATENCY_WEIGHT = float(config.get("ROUTE_SCORE_LATENCY_WEIGHT", ROUTE_SCORE_LATENCY_WEIGHT))
                ROUTE_SCORE_FAIL_WEIGHT = float(config.get("ROUTE_SCORE_FAIL_WEIGHT", ROUTE_SCORE_FAIL_WEIGHT))
                ROUTE_SCORE_RECENCY_WEIGHT = float(config.get("ROUTE_SCORE_RECENCY_WEIGHT", ROUTE_SCORE_RECENCY_WEIGHT))
                ROUTE_SCORE_RECENCY_CAP_SEC = float(config.get("ROUTE_SCORE_RECENCY_CAP_SEC", ROUTE_SCORE_RECENCY_CAP_SEC))
                ROUTE_EWMA_ALPHA = float(config.get("ROUTE_EWMA_ALPHA", ROUTE_EWMA_ALPHA))
                ROUTE_SCORE_NEUTRAL_LATENCY_MS = float(config.get("ROUTE_SCORE_NEUTRAL_LATENCY_MS", ROUTE_SCORE_NEUTRAL_LATENCY_MS))
                ROUTE_SCORE_FAIL_CAP = int(config.get("ROUTE_SCORE_FAIL_CAP", ROUTE_SCORE_FAIL_CAP))
                ROUTE_FAIL_WEIGHT_GENERIC = float(config.get("ROUTE_FAIL_WEIGHT_GENERIC", ROUTE_FAIL_WEIGHT_GENERIC))
                ROUTE_FAIL_WEIGHT_TIMEOUT = float(config.get("ROUTE_FAIL_WEIGHT_TIMEOUT", ROUTE_FAIL_WEIGHT_TIMEOUT))
                ROUTE_FAIL_WEIGHT_CONNECT_ERROR = float(config.get("ROUTE_FAIL_WEIGHT_CONNECT_ERROR", ROUTE_FAIL_WEIGHT_CONNECT_ERROR))
                ROUTE_FAIL_WEIGHT_TLS_ERROR = float(config.get("ROUTE_FAIL_WEIGHT_TLS_ERROR", ROUTE_FAIL_WEIGHT_TLS_ERROR))
                ROUTE_FAIL_WEIGHT_HTTP_REJECT = float(config.get("ROUTE_FAIL_WEIGHT_HTTP_REJECT", ROUTE_FAIL_WEIGHT_HTTP_REJECT))
                ROUTE_CONNECT_FAIL_WEIGHT = float(config.get("ROUTE_CONNECT_FAIL_WEIGHT", ROUTE_CONNECT_FAIL_WEIGHT))
                ROUTE_NO_DATA_FAIL_WEIGHT = float(config.get("ROUTE_NO_DATA_FAIL_WEIGHT", ROUTE_NO_DATA_FAIL_WEIGHT))
                ROUTE_SLOW_FAIL_WEIGHT = float(config.get("ROUTE_SLOW_FAIL_WEIGHT", ROUTE_SLOW_FAIL_WEIGHT))
                ROUTE_QUARANTINE_CONNECT_THRESHOLD = int(
                    config.get("ROUTE_QUARANTINE_CONNECT_THRESHOLD", ROUTE_QUARANTINE_CONNECT_THRESHOLD)
                )
                ROUTE_QUARANTINE_RECOVERY_BATCH = int(
                    config.get("ROUTE_QUARANTINE_RECOVERY_BATCH", ROUTE_QUARANTINE_RECOVERY_BATCH)
                )
                ROUTE_QUARANTINE_TTL_SEC = float(config.get("ROUTE_QUARANTINE_TTL_SEC", ROUTE_QUARANTINE_TTL_SEC))
                ROUTE_QUARANTINE_TIMEOUT_THRESHOLD = int(
                    config.get(
                        "ROUTE_QUARANTINE_TIMEOUT_THRESHOLD",
                        config.get(
                            "ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD",
                            ROUTE_QUARANTINE_TIMEOUT_THRESHOLD,
                        ),
                    )
                )
                ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD = ROUTE_QUARANTINE_TIMEOUT_THRESHOLD
                ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD = int(config.get("ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD", ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD))
                ROUTE_QUARANTINE_TLS_THRESHOLD = int(config.get("ROUTE_QUARANTINE_TLS_THRESHOLD", ROUTE_QUARANTINE_TLS_THRESHOLD))

                RACE_BATCH_PRIMARY = max(1, RACE_BATCH_PRIMARY)
                RACE_BATCH_FALLBACK = max(1, RACE_BATCH_FALLBACK)
                RACE_BATCH_MIN = max(1, min(RACE_BATCH_MIN, RACE_BATCH_PRIMARY))
                RACE_BATCH_LOAD_DOWNSTEP = max(0, RACE_BATCH_LOAD_DOWNSTEP)
                RACE_NATIVE_HEADSTART_SEC = max(0.0, RACE_NATIVE_HEADSTART_SEC)
                RACE_PER_IP_TIMEOUT = max(0.2, RACE_PER_IP_TIMEOUT)
                ROUTE_MAX_RACE_MS = max(100, ROUTE_MAX_RACE_MS)
                ROUTE_KNOWN_LATENCY_HEADROOM_MS = max(0.0, ROUTE_KNOWN_LATENCY_HEADROOM_MS)
                PROBE_READ_TIMEOUT = max(2.0, min(8.0, PROBE_READ_TIMEOUT))
                SCAN_RETRY_ATTEMPTS = max(1, min(4, SCAN_RETRY_ATTEMPTS))

                ROUTE_L1_TTL_SEC = max(5.0, ROUTE_L1_TTL_SEC)
                ROUTE_L1_NATIVE_TTL_SEC = max(1.0, ROUTE_L1_NATIVE_TTL_SEC)
                ROUTE_EVICT_FAIL_THRESHOLD = max(1, ROUTE_EVICT_FAIL_THRESHOLD)
                ROUTE_EWMA_ALPHA = min(0.95, max(0.01, ROUTE_EWMA_ALPHA))
                ROUTE_SCORE_RECENCY_CAP_SEC = max(1.0, ROUTE_SCORE_RECENCY_CAP_SEC)
                ROUTE_SCORE_NEUTRAL_LATENCY_MS = max(1.0, ROUTE_SCORE_NEUTRAL_LATENCY_MS)
                ROUTE_SCORE_FAIL_CAP = max(0, ROUTE_SCORE_FAIL_CAP)
                ROUTE_FAIL_WEIGHT_GENERIC = max(0.0, ROUTE_FAIL_WEIGHT_GENERIC)
                ROUTE_FAIL_WEIGHT_TIMEOUT = max(0.0, ROUTE_FAIL_WEIGHT_TIMEOUT)
                ROUTE_FAIL_WEIGHT_CONNECT_ERROR = max(0.0, ROUTE_FAIL_WEIGHT_CONNECT_ERROR)
                ROUTE_FAIL_WEIGHT_TLS_ERROR = max(0.0, ROUTE_FAIL_WEIGHT_TLS_ERROR)
                ROUTE_FAIL_WEIGHT_HTTP_REJECT = max(0.0, ROUTE_FAIL_WEIGHT_HTTP_REJECT)
                ROUTE_CONNECT_FAIL_WEIGHT = max(0.0, ROUTE_CONNECT_FAIL_WEIGHT)
                ROUTE_NO_DATA_FAIL_WEIGHT = max(0.0, ROUTE_NO_DATA_FAIL_WEIGHT)
                ROUTE_SLOW_FAIL_WEIGHT = max(0.0, ROUTE_SLOW_FAIL_WEIGHT)
                ROUTE_QUARANTINE_CONNECT_THRESHOLD = max(1, ROUTE_QUARANTINE_CONNECT_THRESHOLD)
                ROUTE_QUARANTINE_RECOVERY_BATCH = max(1, ROUTE_QUARANTINE_RECOVERY_BATCH)
                ROUTE_QUARANTINE_TTL_SEC = max(1.0, ROUTE_QUARANTINE_TTL_SEC)
                ROUTE_QUARANTINE_TIMEOUT_THRESHOLD = max(1, ROUTE_QUARANTINE_TIMEOUT_THRESHOLD)
                ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD = ROUTE_QUARANTINE_TIMEOUT_THRESHOLD
                ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD = max(1, ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD)
                ROUTE_QUARANTINE_TLS_THRESHOLD = max(1, ROUTE_QUARANTINE_TLS_THRESHOLD)

                if not isinstance(ALWAYS_ROUTE_PATTERNS, list):
                    ALWAYS_ROUTE_PATTERNS = []
                if not isinstance(DO_NOT_ROUTE_PATTERNS, list):
                    DO_NOT_ROUTE_PATTERNS = []

                ALWAYS_ROUTE_PATTERNS = [str(p).strip().lower() for p in ALWAYS_ROUTE_PATTERNS if str(p).strip()]
                DO_NOT_ROUTE_PATTERNS = [str(p).strip().lower() for p in DO_NOT_ROUTE_PATTERNS if str(p).strip()]

                # Drop malformed regex patterns to avoid runtime regex errors in hot path
                def _is_valid_pattern(pattern):
                    if not pattern.startswith("re:"):
                        return True
                    expr = pattern[3:].strip()
                    if not expr:
                        return False
                    try:
                        re.compile(expr)
                        return True
                    except re.error:
                        return False

                ALWAYS_ROUTE_PATTERNS = [p for p in ALWAYS_ROUTE_PATTERNS if _is_valid_pattern(p)]
                DO_NOT_ROUTE_PATTERNS = [p for p in DO_NOT_ROUTE_PATTERNS if _is_valid_pattern(p)]

                def _dedupe(seq):
                    seen = set()
                    out = []
                    for item in seq:
                        if item in seen:
                            continue
                        seen.add(item)
                        out.append(item)
                    return out

                ALWAYS_ROUTE_PATTERNS = _dedupe(ALWAYS_ROUTE_PATTERNS)
                DO_NOT_ROUTE_PATTERNS = _dedupe(DO_NOT_ROUTE_PATTERNS)
                
                if CONNECTION_MODE not in ["white_ip", "dpi_desync", "mixed"]:
                    CONNECTION_MODE = "white_ip"

                stored_profiles = config.get("MMDF_FRONTING_PROFILES")
                if isinstance(stored_profiles, list) and stored_profiles:
                    MMDF_FRONTING_PROFILES = stored_profiles
                
                valid_strats = ["oob", "bad_csum", "ttl", "syn", "rst", "fin", "classic"]
                if not isinstance(DPI_STRATEGIES, list) or not all(s in valid_strats for s in DPI_STRATEGIES):
                    DPI_STRATEGIES = ["oob"]
                
            if DPI_STRATEGIES:
                ACTIVE_DPI_STRATEGY = DPI_STRATEGIES[0]
        except Exception:
            pass

    # Build Verified SNI Pool using desync_pairs.json
    VALIDATED_SNI_POOL = []
    if DPI_IP:
        try:
            pairs = data_store.read_json("desync_pairs.json", default={})
            if not isinstance(pairs, dict):
                pairs = {}
            for sni, ips in pairs.items():
                if DPI_IP in ips:
                    VALIDATED_SNI_POOL.append(sni)
        except Exception:
            pass
            
    # Fallback to configured target if we have no test data
    if not VALIDATED_SNI_POOL and DPI_SNI:
        VALIDATED_SNI_POOL = [DPI_SNI]

    touch_route_policy()

def save_config():
    config = {
        "MAX_CONCURRENT_SCANS": MAX_CONCURRENT_SCANS,
        "TUNED_MASSCAN_RATE": TUNED_MASSCAN_RATE,
        "TUNED_NMAP_MIN_RATE": TUNED_NMAP_MIN_RATE,
        "TUNED_NMAP_MAX_RATE": TUNED_NMAP_MAX_RATE,
        "CONNECTION_MODE": CONNECTION_MODE,
        "DPI_SNI": DPI_SNI,
        "DPI_IP": DPI_IP,
        "MMDF_SNI": MMDF_SNI,
        "MMDF_IP": MMDF_IP,
        "DPI_STRATEGIES": DPI_STRATEGIES,
        "DPI_FRAGMENTATION": DPI_FRAGMENTATION,
        "ALWAYS_ROUTE_PATTERNS": ALWAYS_ROUTE_PATTERNS,
        "DO_NOT_ROUTE_PATTERNS": DO_NOT_ROUTE_PATTERNS,
        "TARGET_PORTS": TARGET_PORTS,
        "LAST_TARGET_PORTS": LAST_TARGET_PORTS,
        "RACE_BATCH_PRIMARY": RACE_BATCH_PRIMARY,
        "RACE_BATCH_FALLBACK": RACE_BATCH_FALLBACK,
        "RACE_BATCH_MIN": RACE_BATCH_MIN,
        "RACE_BATCH_LOAD_DOWNSTEP": RACE_BATCH_LOAD_DOWNSTEP,
        "RACE_NATIVE_HEADSTART_SEC": RACE_NATIVE_HEADSTART_SEC,
        "RACE_PER_IP_TIMEOUT": RACE_PER_IP_TIMEOUT,
        "ROUTE_MAX_RACE_MS": ROUTE_MAX_RACE_MS,
        "ROUTE_KNOWN_LATENCY_HEADROOM_MS": ROUTE_KNOWN_LATENCY_HEADROOM_MS,
        "PROBE_READ_TIMEOUT": PROBE_READ_TIMEOUT,
        "SCAN_RETRY_ATTEMPTS": SCAN_RETRY_ATTEMPTS,
        "ROUTE_L1_TTL_SEC": ROUTE_L1_TTL_SEC,
        "ROUTE_L1_NATIVE_TTL_SEC": ROUTE_L1_NATIVE_TTL_SEC,
        "ROUTE_EVICT_FAIL_THRESHOLD": ROUTE_EVICT_FAIL_THRESHOLD,
        "ROUTE_SCORE_LATENCY_WEIGHT": ROUTE_SCORE_LATENCY_WEIGHT,
        "ROUTE_SCORE_FAIL_WEIGHT": ROUTE_SCORE_FAIL_WEIGHT,
        "ROUTE_SCORE_RECENCY_WEIGHT": ROUTE_SCORE_RECENCY_WEIGHT,
        "ROUTE_SCORE_RECENCY_CAP_SEC": ROUTE_SCORE_RECENCY_CAP_SEC,
        "ROUTE_EWMA_ALPHA": ROUTE_EWMA_ALPHA,
        "ROUTE_SCORE_NEUTRAL_LATENCY_MS": ROUTE_SCORE_NEUTRAL_LATENCY_MS,
        "ROUTE_SCORE_FAIL_CAP": ROUTE_SCORE_FAIL_CAP,
        "ROUTE_FAIL_WEIGHT_GENERIC": ROUTE_FAIL_WEIGHT_GENERIC,
        "ROUTE_FAIL_WEIGHT_TIMEOUT": ROUTE_FAIL_WEIGHT_TIMEOUT,
        "ROUTE_FAIL_WEIGHT_CONNECT_ERROR": ROUTE_FAIL_WEIGHT_CONNECT_ERROR,
        "ROUTE_FAIL_WEIGHT_TLS_ERROR": ROUTE_FAIL_WEIGHT_TLS_ERROR,
        "ROUTE_FAIL_WEIGHT_HTTP_REJECT": ROUTE_FAIL_WEIGHT_HTTP_REJECT,
        "ROUTE_CONNECT_FAIL_WEIGHT": ROUTE_CONNECT_FAIL_WEIGHT,
        "ROUTE_NO_DATA_FAIL_WEIGHT": ROUTE_NO_DATA_FAIL_WEIGHT,
        "ROUTE_SLOW_FAIL_WEIGHT": ROUTE_SLOW_FAIL_WEIGHT,
        "ROUTE_QUARANTINE_TTL_SEC": ROUTE_QUARANTINE_TTL_SEC,
        "ROUTE_QUARANTINE_CONNECT_THRESHOLD": ROUTE_QUARANTINE_CONNECT_THRESHOLD,
        "ROUTE_QUARANTINE_RECOVERY_BATCH": ROUTE_QUARANTINE_RECOVERY_BATCH,
        "ROUTE_QUARANTINE_TIMEOUT_THRESHOLD": ROUTE_QUARANTINE_TIMEOUT_THRESHOLD,
        "ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD": ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD,
        "ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD": ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD,
        "ROUTE_QUARANTINE_TLS_THRESHOLD": ROUTE_QUARANTINE_TLS_THRESHOLD,
        "MMDF_FRONTING_PROFILES": MMDF_FRONTING_PROFILES,
    }
    try:
        storage.atomic_write_json(CONFIG_FILE, config, indent=4)
    except Exception:
        pass
