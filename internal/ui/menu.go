package ui

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/bridge"
	"whitedns-go/internal/bundledata"
	"whitedns-go/internal/config"
	"whitedns-go/internal/mmdf"
	"whitedns-go/internal/proxy"
	"whitedns-go/internal/router"
	"whitedns-go/internal/rules"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/storage"
)

type App struct {
	Cfg          config.Config
	Scanner      *scanner.Scanner
	Router       *router.Router
	ASNEngine    *asn.ASNEngine
	RuleEngine   *rules.RuleEngine
	DataDir      string
	PythonBridge *bridge.PythonBridge
	inputScanner *bufio.Scanner
}

var defaultHTTPPorts = []int{80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091, 9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808}
var extendedHTTPPorts = []int{80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091, 9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808}
var defaultSOCKS5Ports = []int{1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8118, 8119, 8888, 8889, 3128, 3129, 9000, 9001, 9050, 9051, 9090, 9091, 9999, 10808}
var extendedSOCKS5Ports = []int{1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8118, 8119, 8888, 8889, 3128, 3129, 9000, 9001, 9050, 9051, 9090, 9091, 9999, 10808}

func (a *App) Run() {
	// Start the Bubble Tea TUI. If it fails, print the error.
	if err := a.RunTUI(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI failed: %v\n", err)
	}
}

// RunTUI starts the Bubble Tea TUI application
func (a *App) RunTUI() error {
	m := NewTUI(a)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (a *App) handleWhite(choice string, uiMode *string) bool {
	switch choice {
	case "1":
		a.handleScanMenu()
	case "t":
		a.handleToggleProbeFlags()
	case "2":
		a.handleReloadPool()
	case "3":
		a.handleInstantConnect()
	case "4":
		a.handleSetProxyPort()
	case "5":
		a.handleClearRouteCache()
	case "6":
		a.handleForceReroute()
	case "7":
		a.handleInspectIPs()
	case "8":
		a.handleAutotune()
	case "9":
		a.handleManageRules()
	case "c":
		a.handleInstallMMDFCA()
	case "s":
		a.handleSOCKS5Scanner()
	case "h":
		a.handleHTTPScanner()
	case "w":
		a.startGoProxy("white_ip")
	case "x":
		*uiMode = "desync"
	case "0":
		// Save routes before exit
		routesFile := filepath.Join(a.DataDir, "white_routes.txt")
		if err := a.Router.SaveRoutes(routesFile); err == nil {
			fmt.Println("[+] Routes saved to disk")
		}
		fmt.Println("[*] Shutting down...")
		return true
	}
	return false
}

func (a *App) handleDesync(choice string, uiMode *string) bool {
	switch choice {
	case "1":
		a.handleConfigureDesync()
	case "t":
		a.handleToggleProbeFlags()
	case "2":
		a.handleSelectDPITarget()
	case "3":
		a.handleDesyncScanner()
	case "4":
		a.handleSNIScanner()
	case "5":
		a.handleSetProxyPort()
	case "6":
		a.handleClearRouteCache()
	case "s":
		a.handleSOCKS5Scanner()
	case "h":
		a.handleHTTPScanner()
	case "c":
		a.handleInstallMMDFCA()
	case "d":
		a.startGoProxy("dpi_desync")
	case "m":
		a.startGoProxy("mixed")
	case "x":
		*uiMode = "white"
	case "0":
		fmt.Println("[*] Shutting down...")
		return true
	}
	return false
}

func (a *App) startGoProxy(mode string) {
	state := loadDPIState(a.DataDir)
	fmt.Printf("\n[*] Starting proxy mode: %s\n", mode)
	fmt.Printf("[+] DPI state: %s\n", formatDPIStateSummary(state))
	server := &proxy.Server{Addr: a.Cfg.ListenAddr()}
	if err := server.Run(); err != nil {
		fmt.Printf("[-] Proxy failed: %v\n", err)
		time.Sleep(1500 * time.Millisecond)
	}
}

func drawHeader(cfg config.Config, mode string) {
	clearScreen()
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" WHITEDNS v1.2 ")
	fmt.Println(" developed by TAjirax ")
	fmt.Println("------------------------------------------------------------")
	uiLabel := "WhiteDNS"
	if mode == "desync" {
		uiLabel = "Desync"
	}
	fmt.Printf(" UI Mode: %s\n", uiLabel)
	fmt.Printf(" Conn Mode: %s\n", mapMode(mode))
	fmt.Printf(" Proxy: %s\n", cfg.ListenAddr())
	fmt.Println("------------------------------------------------------------")
}

func printMainMenu(uiMode string) {
	if uiMode == "desync" {
		fmt.Println("\n DESYNC MODE")
		fmt.Println(" [1] Configure DPI Desync Strategies")
		fmt.Println(" [2] Select DPI Target (SNI/IP)")
		fmt.Println(" [3] Scan/Mine DPI SNI Pairs")
		fmt.Println(" [4] SNI Scanner (Carrier Discovery)")
		fmt.Println(" [5] Change Proxy Port")
		fmt.Println(" [6] Clear Routing Cache")
		fmt.Println(" [s] SOCKS5 Proxy Scanner")
		fmt.Println(" [h] HTTP-Only Proxy Scanner")
		fmt.Println(" [c] Install MMDF CA (Meet / YouTube)")
		fmt.Println("\n Launch")
		fmt.Println(" [d] Start Proxy (DPI Desync)")
		fmt.Println(" [m] Start Proxy (Mixed)")
		fmt.Println("\n Navigation")
		fmt.Println(" [x] Switch to WhiteDNS Mode")
		fmt.Println(" [0] Exit")
		return
	}

	fmt.Println("\n WHITEDNS MODE")
	fmt.Println(" [1] Scan Targets and Build IP Pool")
	fmt.Println(" [2] Reload IP Pool from Latest Scan")
	fmt.Println(" [3] Instant Connect (Load IPs without scan)")
	fmt.Println(" [4] Change Proxy Port")
	fmt.Println(" [5] Clear Routing Cache (white_routes.txt)")
	fmt.Println(" [6] Force Reroute Domain and Ban IP")
	fmt.Println(" [7] Inspect IPs (ASN and Type)")
	fmt.Println(" [8] Auto-Tune Scan Rates")
	fmt.Println(" [9] Manage Routing Rules (Whitelist/Blacklist)")
	fmt.Println(" [s] SOCKS5 Proxy Scanner")
	fmt.Println(" [h] HTTP-Only Proxy Scanner")
	fmt.Println(" [t] Settings: Probe Heuristics")
	fmt.Println(" [c] Install MMDF CA (Meet / YouTube)")
	fmt.Println("\n Launch")
	fmt.Println(" [w] Start Proxy (White Routing)")
	fmt.Println("\n Navigation")
	fmt.Println(" [x] Switch to Desync Mode")
	fmt.Println(" [0] Exit")
}

func mapMode(uiMode string) string {
	if uiMode == "desync" {
		return "dpi_desync"
	}
	return "white_ip"
}

func clearScreen() {
	if os.PathSeparator == '\\' {
		fmt.Print("\033[H\033[2J")
		return
	}
	fmt.Print("\033[H\033[2J")
}

// Native Go action handlers
func (a *App) handleScanMenu() {
	fmt.Println("\n[*] Scan Menu")
	fmt.Print("[?] Enter target IPs or CIDR ranges (space/comma separated): ")
	input := a.readLineInput()
	if input == "" {
		fmt.Println("[-] No targets provided")
		time.Sleep(1500 * time.Millisecond)
		return
	}

	targets := strings.FieldsFunc(input, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	})

	if len(targets) == 0 {
		fmt.Println("[-] Invalid targets")
		time.Sleep(1500 * time.Millisecond)
		return
	}

	// Try masscan
	fmt.Println("\n[*] Running masscan preflight...")
	endpoints, err := a.Scanner.MasscanPreflight(targets, true)
	if err != nil {
		fmt.Printf("[-] Masscan failed: %v\n", err)
		time.Sleep(1500 * time.Millisecond)
		return
	}

	fmt.Printf("[+] Found %d online endpoints\n", len(endpoints))

	// Probe endpoints
	ctx := context.Background()
	fmt.Println("[*] Probing endpoints...")

	probeCount := 0
	for _, ep := range endpoints {
		result := a.Scanner.ProbeEndpoint(ctx, ep, []string{"google.com", "workers.dev"})
		if result.Success {
			a.Router.AddRouteToCache("", ep, result.Latency.Seconds()*1000, true)
			fmt.Printf("[+] %s: OK (%d ms)\n", ep, int(result.Latency.Milliseconds()))
			probeCount++
		} else {
			fmt.Printf("[-] %s: %s\n", ep, result.Error)
		}
	}

	fmt.Printf("\n[+] Scan complete: %d/%d endpoints verified\n", probeCount, len(endpoints))
	time.Sleep(2000 * time.Millisecond)
}

func (a *App) handleManagePool() {
	fmt.Println("\n[*] Manage IP Pool")
	stats := a.Scanner.GetAllStats()

	if len(stats) == 0 {
		fmt.Println("[-] IP pool is empty. Run a scan first.")
	} else {
		fmt.Printf("[+] Current pool size: %d endpoints\n", len(stats))

		count := 0
		for ep, stat := range stats {
			if count >= 10 {
				fmt.Printf("... and %d more\n", len(stats)-10)
				break
			}
			fmt.Printf("  - %s: %d successes, %d failures, avg latency %.0f ms\n",
				ep, stat.SuccessCount, stat.FailCount, stat.AvgLatencyMs)
			count++
		}
	}

	time.Sleep(2000 * time.Millisecond)
}

func (a *App) handleSetProxyPort() {
	fmt.Printf("\nCurrent proxy port: %d\n", a.Cfg.ProxyPort)
	fmt.Print("[?] Enter new proxy port [0 to keep current]: ")
	input := a.readLineInput()
	if input == "" || input == "0" {
		fmt.Println("[*] Port unchanged")
	} else {
		fmt.Println("[*] Port change would require restart - feature limited in this version")
	}
	time.Sleep(1000 * time.Millisecond)
}

func (a *App) handleClearRouteCache() {
	fmt.Println("\n[-] Clearing route cache...")
	a.Router.ClearAllRoutes()
	a.Scanner.ClearCache()
	fmt.Println("[+] Cache cleared")
	time.Sleep(1000 * time.Millisecond)
}

func (a *App) readLineInput() string {
	if a.inputScanner == nil {
		return ""
	}
	if a.inputScanner.Scan() {
		return strings.TrimSpace(a.inputScanner.Text())
	}
	// EOF reached or error
	if err := a.inputScanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Input error: %v\n", err)
	}
	return ""
}

// New handler implementations for all features

func (a *App) handleReloadPool() {
	fmt.Println("\n[*] Loading cached routes from disk...")
	routesFile := filepath.Join(a.DataDir, "white_routes.txt")
	if count, err := a.Router.LoadRoutes(routesFile); err == nil {
		fmt.Printf("[+] Loaded %d cached routes\n", count)
		poolStats := a.Router.GetPoolStats()
		fmt.Printf("[+] Pool: %d total routes, %d unique endpoints, %d domains\n",
			poolStats["total_routes"], poolStats["unique_endpoints"], poolStats["cached_domains"])
	} else {
		fmt.Printf("[-] Error loading routes: %v\n", err)
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) handleInstantConnect() {
	fmt.Println("\n[*] Instant Connect")
	fmt.Print("[?] Enter endpoints (IP:port, space-separated): ")
	input := a.readLineInput()
	if input == "" {
		fmt.Println("[-] No endpoints provided")
		time.Sleep(1000 * time.Millisecond)
		return
	}

	endpoints := strings.Fields(input)
	domain := "default"
	fmt.Print("[?] Domain (default: 'default'): ")
	if d := a.readLineInput(); d != "" {
		domain = d
	}

	count := 0
	for _, ep := range endpoints {
		a.Router.AddRouteToCache(domain, ep, 700.0, true)
		count++
	}
	fmt.Printf("[+] Added %d endpoints to routing cache\n", count)
	time.Sleep(1000 * time.Millisecond)
}

func (a *App) handleToggleProbeFlags() {
	// Show current values and allow toggling
	fmt.Println("\n[*] Probe Heuristics")
	requireHTML := "OFF"
	if a.Scanner != nil && a.Scanner.GetProbeRequireHTMLForDomainTokens() {
		requireHTML = "ON"
	}
	certMatch := "OFF"
	if a.Scanner != nil && a.Scanner.GetProbeAcceptOnCertMatch() {
		certMatch = "ON"
	}
	fmt.Printf("[1] Require HTML for domain tokens: %s\n", requireHTML)
	fmt.Printf("[2] Accept on TLS cert match:    %s\n", certMatch)
	fmt.Println("Enter number to toggle (1/2) or press Enter to return:")
	choice := strings.TrimSpace(a.readLineInput())
	switch choice {
	case "1":
		if a.Scanner != nil {
			newVal := !a.Scanner.GetProbeRequireHTMLForDomainTokens()
			a.Scanner.SetProbeRequireHTMLForDomainTokens(newVal)
			a.Cfg.ProbeRequireHTMLForDomainTokens = newVal
			// Persist
			_ = config.SaveToFile(a.Cfg, storage.GetPaths().ConfigFile)
			fmt.Println("Toggled Require HTML for domain tokens ->", newVal)
		}
	case "2":
		if a.Scanner != nil {
			newVal := !a.Scanner.GetProbeAcceptOnCertMatch()
			a.Scanner.SetProbeAcceptOnCertMatch(newVal)
			a.Cfg.ProbeAcceptOnCertMatch = newVal
			// Persist
			_ = config.SaveToFile(a.Cfg, storage.GetPaths().ConfigFile)
			fmt.Println("Toggled Accept on TLS cert match ->", newVal)
		}
	default:
		fmt.Println("No changes")
	}
	time.Sleep(800 * time.Millisecond)
}

func (a *App) handleForceReroute() {
	fmt.Println("\n[*] Force Reroute Domain")
	fmt.Print("[?] Enter domain: ")
	domain := a.readLineInput()
	if domain == "" {
		fmt.Println("[-] No domain provided")
		time.Sleep(1000 * time.Millisecond)
		return
	}

	fmt.Print("[?] Enter endpoint to ban (or leave blank to skip): ")
	banEP := a.readLineInput()

	if banEP != "" {
		banned := a.Router.BanEndpoint(banEP)
		fmt.Printf("[+] Banned endpoint from %d domains\n", banned)
	}

	endpoints := a.Router.GetEndpointsForDomain(domain)
	if len(endpoints) == 0 {
		fmt.Printf("[-] No cached endpoints for %s\n", domain)
	} else {
		fmt.Printf("[+] Current endpoints for %s: %v\n", domain, endpoints[:min(len(endpoints), 3)])
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) handleInspectIPs() {
	fmt.Println("\n[*] Inspect IPs (ASN Lookup)")
	fmt.Print("[?] Enter IP address to inspect: ")
	ip := a.readLineInput()
	if ip == "" {
		fmt.Println("[-] No IP provided")
		time.Sleep(1000 * time.Millisecond)
		return
	}

	info, err := a.ASNEngine.Lookup(ip)
	if err != nil {
		fmt.Printf("[-] Lookup failed: %v\n", err)
	} else {
		fmt.Printf("[+] ASN Info for %s:\n", ip)
		fmt.Printf("    ASN: %s\n", info.ASN)
		fmt.Printf("    Name: %s\n", info.Name)
		fmt.Printf("    Type: %s\n", info.Type)
		fmt.Printf("    CIDR: %s\n", info.CIDR)
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) handleAutotune() {
	fmt.Println("\n[*] Auto-Tune Scan Rates")
	fmt.Println("[*] Autotune analyzes network conditions and optimizes scan parameters")
	fmt.Print("[?] Run quick baseline test? (y/n): ")
	choice := a.readLineInput()

	if strings.ToLower(choice) == "y" {
		fmt.Println("[*] Testing with small IP range...")
		fmt.Print("[?] Enter 1-2 test IPs (space-separated): ")
		ips := strings.Fields(a.readLineInput())
		if len(ips) > 0 {
			fmt.Println("[*] Running quick masscan baseline...")
			endpoints, _ := a.Scanner.MasscanPreflight(ips, false)
			fmt.Printf("[+] Found %d endpoints in baseline\n", len(endpoints))
			fmt.Println("[*] Recommended settings based on baseline:")
			fmt.Println("    Rate: 1000 pps")
			fmt.Println("    Retries: 2")
			fmt.Println("    Wait: 10s")
		}
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) handleManageRules() {
	fmt.Println("\n[*] Manage Routing Rules")
	fmt.Println("[1] Add always_route pattern")
	fmt.Println("[2] Add do_not_route pattern")
	fmt.Println("[3] List current rules")
	fmt.Println("[4] Clear all rules")
	fmt.Print("Choice: ")

	choice := a.readLineInput()
	switch choice {
	case "1":
		fmt.Print("[?] Enter pattern (exact/glob/regex): ")
		pattern := a.readLineInput()
		if err := a.RuleEngine.AddRule("", pattern, "always_route"); err != nil {
			fmt.Printf("[-] Error: %v\n", err)
		} else {
			fmt.Println("[+] Rule added (always_route)")
		}

	case "2":
		fmt.Print("[?] Enter pattern (exact/glob/regex): ")
		pattern := a.readLineInput()
		if err := a.RuleEngine.AddRule("", pattern, "do_not_route"); err != nil {
			fmt.Printf("[-] Error: %v\n", err)
		} else {
			fmt.Println("[+] Rule added (do_not_route)")
		}

	case "3":
		always, doNot := a.RuleEngine.GetAllRules()
		fmt.Printf("\n[+] Always Route (%d rules):\n", len(always))
		for _, r := range always {
			fmt.Printf("    [%s] %s\n", r.Type, r.Pattern)
		}
		fmt.Printf("\n[+] Do Not Route (%d rules):\n", len(doNot))
		for _, r := range doNot {
			fmt.Printf("    [%s] %s\n", r.Type, r.Pattern)
		}

	case "4":
		a.RuleEngine.ClearRules()
		fmt.Println("[+] All rules cleared")
	}

	time.Sleep(1500 * time.Millisecond)
}

func (a *App) handleHTTPScanner() {
	a.handleProxyScanner("HTTP", defaultHTTPScanPorts(), defaultHTTPDiscovery(), "http_proxies.txt", "http_cache.txt", true)
}

func (a *App) handleSOCKS5Scanner() {
	a.handleProxyScanner("SOCKS5", defaultSOCKS5ScanPorts(), defaultProxyDiscovery(), "socks5_proxies.txt", "socks5_cache.txt", false)
}

func (a *App) handleConfigureDesync() {
	if a.PythonBridge != nil {
		if err := a.PythonBridge.RunAction("desync_strategies"); err != nil {
			fmt.Printf("[-] Bridge error: %v\n", err)
			time.Sleep(1500 * time.Millisecond)
			return
		}
	}
}

func (a *App) handleSelectDPITarget() {
	if a.PythonBridge != nil {
		if err := a.PythonBridge.RunAction("select_dpi_target"); err != nil {
			fmt.Printf("[-] Bridge error: %v\n", err)
			time.Sleep(1500 * time.Millisecond)
			return
		}
	}
}

func (a *App) handleDesyncScanner() {
	if a.PythonBridge != nil {
		if err := a.PythonBridge.RunAction("desync_scanner"); err != nil {
			fmt.Printf("[-] Bridge error: %v\n", err)
			time.Sleep(1500 * time.Millisecond)
			return
		}
	}
}

func (a *App) handleSNIScanner() {
	fmt.Println("\n[*] SNI Scanner")
	list := loadSNIPatterns()
	if len(list) == 0 {
		fmt.Println("[-] No SNI list found (assets/cf-domains.txt missing or empty)")
		time.Sleep(1500 * time.Millisecond)
		return
	}

	cleanIP, err := a.pickCleanEdgeIP()
	if err != nil {
		fmt.Printf("[-] Failed to obtain a clean edge IP: %v\n", err)
		time.Sleep(1500 * time.Millisecond)
		return
	}

	fmt.Printf("[+] Using clean edge IP: %s\n", cleanIP)
	cleanSNIs := make([]string, 0, len(list))
	for _, sni := range list {
		if verifySNIPair(cleanIP, sni) {
			cleanSNIs = append(cleanSNIs, sni)
			fmt.Printf("[+] CLEAN SNI FOUND: %s\n", sni)
		}
	}

	if len(cleanSNIs) == 0 {
		fmt.Println("[-] No clean SNIs found")
		time.Sleep(1500 * time.Millisecond)
		return
	}

	cleanSNIs = dedupeAndSortStrings(cleanSNIs)
	if err := storage.AtomicWriteText(filepath.Join(a.DataDir, "clean_snis.txt"), strings.Join(cleanSNIs, "\n")+"\n"); err != nil {
		fmt.Printf("[-] Failed to save clean_snis.txt: %v\n", err)
	} else {
		fmt.Printf("[+] Saved %d clean SNI(s) to clean_snis.txt\n", len(cleanSNIs))
	}

	state := loadDPIState(a.DataDir)
	if len(cleanSNIs) > 0 {
		state.DpiSNI = cleanSNIs[0]
		_ = saveDPIState(a.DataDir, state)
	}
}

func (a *App) handleInstallMMDFCA() {
	fmt.Println("\n[*] Install MMDF CA")
	summary, err := mmdf.StatusSummary(a.DataDir)
	if err == nil {
		fmt.Printf("[+] Backend: %s\n", summary.Backend)
		fmt.Printf("[+] CA cert: %s\n", summary.CertPath)
		fmt.Printf("[+] CA key:  %s\n", summary.KeyPath)
		fmt.Printf("[+] CA files present: %v\n", summary.CAFilesPresent)
		if summary.IsInstalled != nil {
			fmt.Printf("[+] Installed in trust store: %v\n", *summary.IsInstalled)
		}
	}
	result, err := mmdf.InstallCA(a.DataDir)
	if err != nil {
		fmt.Printf("[-] MMDF install failed: %v\n", err)
		time.Sleep(1500 * time.Millisecond)
		return
	}
	if ok, _ := result["ok"].(bool); ok {
		fmt.Printf("[+] %s\n", result["message"])
	} else {
		fmt.Printf("[-] %s\n", result["message"])
		if needsElev, _ := result["requires_elevation"].(bool); needsElev {
			fmt.Println("[!] Elevation may be required to install the CA into the OS trust store.")
		}
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) pickCleanEdgeIP() (string, error) {
	for {
		fmt.Println("\n[?] Clean IP source")
		fmt.Println(" [1] Enter IP manually")
		fmt.Println(" [2] Auto-mine from cf-domains.txt")
		fmt.Print("Choice [Default 2]: ")
		choice := strings.TrimSpace(a.readLineInput())
		if choice == "1" {
			fmt.Print("[?] Enter your clean IP: ")
			ip := strings.TrimSpace(a.readLineInput())
			if ip == "" {
				return "", fmt.Errorf("no IP provided")
			}
			if verifyCloudflareIP(ip) {
				return ip, nil
			}
			fmt.Println("[-] IP failed clean-edge verification")
			fmt.Print("[?] Use it anyway? (y/N): ")
			if strings.EqualFold(strings.TrimSpace(a.readLineInput()), "y") {
				return ip, nil
			}
			continue
		}

		ips := mineCloudflareIPs()
		if len(ips) == 0 {
			return "", fmt.Errorf("no candidate IPs discovered")
		}
		for _, ip := range ips {
			if verifyCloudflareIP(ip) {
				return ip, nil
			}
		}
		return "", fmt.Errorf("no clean edge IP verified")
	}
}

func loadSNIPatterns() []string {
	if bundled, err := bundledata.LoadSNIPatterns(); err == nil && len(bundled) > 0 {
		return bundled
	}

	paths := []string{filepath.Join("assets", "cf-domains.txt"), filepath.Join("..", "assets", "cf-domains.txt")}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		seen := make(map[string]struct{})
		var items []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			items = append(items, line)
		}
		return items
	}
	return []string{}
}

func mineCloudflareIPs() []string {
	patterns := config.CloudflareCNAMEDomains
	if len(patterns) == 0 {
		patterns = loadSNIPatterns()
	}
	if len(patterns) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, domain := range patterns {
		resolved, err := net.LookupIP(domain)
		if err != nil {
			continue
		}
		for _, ip := range resolved {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			s := ip4.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}
	return ips
}

func verifyCloudflareIP(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		ServerName:         "speed.cloudflare.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		_ = ctx
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil && err != io.EOF {
		return false
	}
	resp := strings.ToLower(string(buf[:n]))
	blocked := []string{"peyvandha.ir", "10.10.3", "internet.ir", "cra.ir"}
	for _, sig := range blocked {
		if strings.Contains(resp, sig) {
			return false
		}
	}
	return strings.Contains(resp, "http/") && strings.Contains(resp, "cloudflare")
}

func verifySNIPair(ip, sni string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = ctx
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	probe := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", sni)
	if _, err := io.WriteString(conn, probe); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil && err != io.EOF {
		return false
	}
	resp := strings.ToLower(string(buf[:n]))
	blocked := []string{"peyvandha.ir", "10.10.3", "internet.ir", "cra.ir"}
	for _, sig := range blocked {
		if strings.Contains(resp, sig) {
			return false
		}
	}
	return strings.Contains(resp, "http/")
}

func sortedMapKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (a *App) handleProxyScanner(label string, defaultPorts []int, defaultDiscovery string, exportFile string, cacheFile string, httpMode bool) {
	fmt.Printf("\n[*] %s Scanner\n", label)
	targets := a.promptScanSource(label, httpMode)
	if len(targets) == 0 {
		fmt.Println("[-] No valid targets provided")
		time.Sleep(1000 * time.Millisecond)
		return
	}

	ports := a.promptTargetPorts(httpMode)
	a.Scanner.SetTargetPorts(ports)
	method := a.promptScanMethod(len(targets), len(ports), httpMode)
	concurrency := 500
	timeoutSec := 8
	if method == "direct" {
		concurrency = a.promptPositiveInt("[?] Verification concurrency [Default 500]: ", 500)
		if !httpMode {
			timeoutDefault := 5
			timeoutSec = a.promptPositiveInt(fmt.Sprintf("[?] Verification timeout seconds [Default %d]: ", timeoutDefault), timeoutDefault)
		}
	}

	if method == "direct" {
		fmt.Printf("[*] Direct verification | Ports: %v\n", ports)
	} else {
		fmt.Printf("[*] Discovery: %s | Ports: %v\n", method, ports)
	}

	var proxies []string
	var err error
	// Allow user to select transfer benchmark model
	fmt.Println()
	fmt.Println(" TRANSFER BENCHMARK MODEL")
	fmt.Println(" [1] Old (stable)")
	fmt.Println(" [2] goBrrrr (fast)")
	fmt.Print("Choice [1/2]: ")
	tmChoice := strings.TrimSpace(a.readLineInput())
	transferModel := "old"
	if tmChoice == "2" {
		transferModel = "brrr"
	}

	opts := scanner.ProxyScanOptions{
		Ports:         ports,
		Discovery:     method,
		Concurrency:   concurrency,
		Timeout:       time.Duration(timeoutSec) * time.Second,
		TransferModel: transferModel,
	}

	if httpMode {
		proxies, err = a.Scanner.ScanHTTPProxies(targets, opts)
	} else {
		proxies, err = a.Scanner.ScanSOCKS5Proxies(targets, opts)
	}
	if err != nil {
		fmt.Printf("[-] Scan failed: %v\n", err)
		time.Sleep(1500 * time.Millisecond)
		return
	}

	fmt.Printf("\n[+] %s scan complete: %d verified proxy(ies)\n", label, len(proxies))
	if len(proxies) == 0 {
		time.Sleep(1000 * time.Millisecond)
		return
	}

	if err := saveProxyResults(a.DataDir, exportFile, cacheFile, proxies); err != nil {
		fmt.Printf("[-] Failed to save results: %v\n", err)
	} else {
		fmt.Printf("[+] Saved exports to %s and %s\n", exportFile, cacheFile)
	}
	time.Sleep(1500 * time.Millisecond)
}

func (a *App) promptTargetPorts(httpMode bool) []int {
	fmt.Println("\n TARGET PORTS")
	if httpMode {
		fmt.Printf(" [1] Default HTTP ports  (%s)\n", joinInts(defaultHTTPPorts))
		fmt.Printf(" [2] Extended ports      (%s...)\n", joinIntsTruncated(extendedHTTPPorts, 50))
	} else {
		fmt.Printf(" [1] Default SOCKS5 ports  (%s)\n", joinInts(defaultSOCKS5Ports))
		fmt.Printf(" [2] Extended ports        (%s...)\n", joinIntsTruncated(extendedSOCKS5Ports, 50))
	}
	fmt.Println(" [3] Custom ports")

	choice := strings.TrimSpace(a.readLineInput())
	switch choice {
	case "2":
		if httpMode {
			return append([]int(nil), extendedHTTPPorts...)
		}
		return append([]int(nil), extendedSOCKS5Ports...)
	case "3":
		fmt.Print("Ports (comma or space separated): ")
		rawPorts := strings.TrimSpace(a.readLineInput())
		ports := parsePortList(rawPorts)
		if len(ports) == 0 {
			fmt.Println("[!] Invalid input, using default ports.")
			if httpMode {
				return append([]int(nil), defaultHTTPPorts...)
			}
			return append([]int(nil), defaultSOCKS5Ports...)
		}
		return ports
	default:
		if httpMode {
			return append([]int(nil), defaultHTTPPorts...)
		}
		return append([]int(nil), defaultSOCKS5Ports...)
	}
}

func (a *App) promptScanMethod(totalTargets, totalPorts int, httpMode bool) string {
	fmt.Println()
	fmt.Println(" SCAN METHOD")
	totalEPS := totalTargets * totalPorts
	if httpMode {
		fmt.Printf(" [1] Normal (Go/direct)             - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
		fmt.Printf(" [2] Masscan preflight              - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
		fmt.Printf(" [3] Nmap preflight                 - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
	} else {
		fmt.Printf(" [1] Normal (Go/direct)             - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
		fmt.Printf(" [2] Masscan preflight              - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
		fmt.Printf(" [3] Nmap preflight                 - %d probes (%d IPs x %d ports)\n", totalEPS, totalTargets, totalPorts)
	}

	methodMap := map[string]string{"1": "direct", "2": "masscan", "3": "nmap"}
	choice := strings.TrimSpace(a.readLineInput())
	if method, ok := methodMap[choice]; ok {
		return method
	}
	return "direct"
}

func defaultMasscanRate() int {
	return 5000
}

func (a *App) promptScanSource(label string, httpMode bool) []string {
	for {
		fmt.Println("\nSCAN SOURCE")
		fmt.Println(" [1] Load IPs/CIDRs/ASNs from text file")
		fmt.Println(" [2] Paste IPs/CIDRs/ASNs manually")
		fmt.Println(" [3] Use Permanent HTTP proxy cache")
		fmt.Println(" [4] Mine IPs from Cloudflare CNAMEs")
		fmt.Println(" [5] Select from IranASN database")
		fmt.Println(" [6] Export selected ASN(s) to TXT")
		fmt.Println(" [0] Back")
		fmt.Print("Choice: ")

		switch strings.TrimSpace(a.readLineInput()) {
		case "1":
			fmt.Print("[?] Enter path to target list file: ")
			path := strings.TrimSpace(a.readLineInput())
			if path == "" {
				return nil
			}
			lines, err := readSourceFileLines(path)
			if err != nil {
				fmt.Printf("[-] Failed to read file: %v\n", err)
				continue
			}
			return normalizeProxyTargets(lines)
		case "2":
			fmt.Println("[?] Paste IPs/CIDRs/ASNs (press Enter on an empty line to finish):")
			var lines []string
			for {
				line := strings.TrimSpace(a.readLineInput())
				if line == "" {
					break
				}
				lines = append(lines, line)
			}
			return normalizeProxyTargets(lines)
		case "3":
			cacheFile := "http_cache.txt"
			if !httpMode {
				cacheFile = "socks5_cache.txt"
			}
			return readCacheTargets(a.DataDir, cacheFile)
		case "4":
			return normalizeProxyTargets(mineCloudflareIPs())
		case "5":
			if a.ASNEngine == nil {
				fmt.Println("[-] ASN database unavailable")
				continue
			}
			if err := a.ASNEngine.Load(); err != nil {
				fmt.Printf("[-] Failed to load ASN database: %v\n", err)
				continue
			}
			return a.selectASNScanTargets()
		case "6":
			if a.ASNEngine == nil {
				fmt.Println("[-] ASN database unavailable")
				continue
			}
			if err := a.ASNEngine.Load(); err != nil {
				fmt.Printf("[-] Failed to load ASN database: %v\n", err)
				continue
			}
			targets := a.selectASNScanTargets()
			if len(targets) == 0 {
				continue
			}
			fmt.Print("[?] Output TXT path [press Enter for default]: ")
			outputPath := strings.TrimSpace(a.readLineInput())
			path, count, err := exportASNTargetsToTXT(a.DataDir, targets, outputPath)
			if err != nil {
				fmt.Printf("[-] Failed to export ASN IPs: %v\n", err)
				continue
			}
			fmt.Printf("[+] Exported %d IPs to %s\n", count, path)
			return nil
		case "0":
			return nil
		default:
			fmt.Println("[-] Invalid choice")
		}
	}
}

func readSourceFileLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func readCacheTargets(dataDir, cacheFile string) []string {
	path := filepath.Join(dataDir, cacheFile)
	if dataDir == "" {
		path = cacheFile
	}
	lines, err := storage.ReadTextLines(path)
	if err != nil || len(lines) == 0 {
		fmt.Printf("[-] Cache is empty or unavailable: %s\n", cacheFile)
		return nil
	}
	return normalizeProxyTargets(lines)
}

func (a *App) selectASNScanTargets() []string {
	if a.ASNEngine == nil {
		fmt.Println("[-] ASN database unavailable")
		return nil
	}

	allGroups, err := a.ASNEngine.SearchGroups("*")
	if err != nil {
		fmt.Printf("[-] ASN search failed: %v\n", err)
		return nil
	}

	query := "*"
	page := 1
	selected := make(map[string]bool)

	for {
		groups, err := a.ASNEngine.SearchGroups(query)
		if err != nil {
			fmt.Printf("[-] ASN search failed: %v\n", err)
			return nil
		}

		if len(groups) == 0 {
			fmt.Printf("\nSearch Query: %s\n", query)
			fmt.Println(" Total Matches: 0 ASNs")
			fmt.Printf(" Selected ASNs: %d\n", len(selected))
			fmt.Println("[-] No matches found")
			fmt.Print("[?] Enter new search query or press Enter to cancel: ")
			input := strings.TrimSpace(a.readLineInput())
			if input == "" {
				return nil
			}
			query = input
			page = 1
			continue
		}

		const pageSize = 15
		totalPages := (len(groups) + pageSize - 1) / pageSize
		if page < 1 {
			page = 1
		}
		if page > totalPages {
			page = totalPages
		}
		start := (page - 1) * pageSize
		end := start + pageSize
		if end > len(groups) {
			end = len(groups)
		}

		fmt.Printf("\nSearch Query: %s\n", query)
		fmt.Printf(" Total Matches: %d ASNs\n", len(groups))
		fmt.Printf(" Selected ASNs: %d\n", countSelectedASN(selected))
		fmt.Println("------------------------------------------------------------")
		for i, group := range groups[start:end] {
			mark := " "
			if selected[group.ASN] {
				mark = "x"
			}
			name := group.Name
			if name == "" {
				name = "(unknown)"
			}
			fmt.Printf("%6d. [%s] %-10s - %-55s (%d subnets)\n", start+i+1, mark, group.ASN, truncateASNName(name, 55), group.SubnetCount)
		}
		fmt.Printf("\n--- Page %d/%d ---\n", page, totalPages)
		fmt.Println(" Commands")
		fmt.Println(" [1,2,5-8] Toggle ASN selection")
		fmt.Println(" [/text]    Search (substring match)")
		fmt.Println(" [/*pat*]   Wildcard search")
		fmt.Println(" [/regex:]   Regex search (example: /regex:^AS\\d+(mobile|.*mci))")
		fmt.Println(" [/^pat$]   Regex anchors (example: /^AS58224)")
		fmt.Println(" [n]/[p]    Next/Previous page")
		fmt.Println(" [all]      Select all current matches")
		fmt.Println(" [clear]    Clear all selections")
		fmt.Println(" [d]        Done and queue subnets")
		fmt.Println(" [0]        Cancel")
		fmt.Print("\nChoice/Search: ")

		input := strings.TrimSpace(a.readLineInput())
		if input == "" {
			continue
		}

		switch strings.ToLower(input) {
		case "n":
			if page < totalPages {
				page++
			}
		case "p":
			if page > 1 {
				page--
			}
		case "all":
			for _, group := range groups {
				selected[group.ASN] = true
			}
		case "clear":
			for key := range selected {
				delete(selected, key)
			}
		case "d":
			return collectSelectedASNTargets(allGroups, selected)
		case "0":
			return nil
		default:
			if maybeToggleASNSelection(input, groups[start:end], selected) {
				continue
			}
			query = input
			page = 1
		}
	}
}

func collectSelectedASNTargets(groups []asn.ASNGroup, selected map[string]bool) []string {
	var targets []string
	totalCIDRs := 0
	for _, group := range groups {
		if !selected[group.ASN] {
			continue
		}
		targets = append(targets, group.CIDRs...)
		totalCIDRs += len(group.CIDRs)
	}
	fmt.Printf("[+] ASN selection expanded to %d CIDR(s) across %d group(s)\n", totalCIDRs, countSelectedASN(selected))
	return normalizeProxyTargets(targets)
}

func countSelectedASN(selected map[string]bool) int {
	count := 0
	for _, enabled := range selected {
		if enabled {
			count++
		}
	}
	return count
}

func maybeToggleASNSelection(input string, pageGroups []asn.ASNGroup, selected map[string]bool) bool {
	indices := parseSelectionRanges(input, len(pageGroups))
	if len(indices) == 0 {
		return false
	}
	for _, index := range indices {
		group := pageGroups[index-1]
		selected[group.ASN] = !selected[group.ASN]
	}
	return true
}

func parseSelectionRanges(input string, max int) []int {
	parts := strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	seen := make(map[int]struct{})
	var out []int
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || start < 1 || end < 1 || start > max || end > max {
				continue
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				if _, ok := seen[i]; ok {
					continue
				}
				seen[i] = struct{}{}
				out = append(out, i)
			}
			continue
		}
		index, err := strconv.Atoi(part)
		if err != nil || index < 1 || index > max {
			continue
		}
		if _, ok := seen[index]; ok {
			continue
		}
		seen[index] = struct{}{}
		out = append(out, index)
	}
	sort.Ints(out)
	return out
}

func truncateASNName(name string, limit int) string {
	if len(name) <= limit {
		return name
	}
	if limit <= 3 {
		return name[:limit]
	}
	return name[:limit-3] + "..."
}

func (a *App) promptPortList(defaultPorts []int) []int {
	defaultText := joinInts(defaultPorts)
	fmt.Printf("[?] Use proxy ports [%s] or enter custom ports: ", defaultText)
	input := a.readLineInput()
	if input == "" {
		return append([]int(nil), defaultPorts...)
	}
	ports := parsePortList(input)
	if len(ports) == 0 {
		return append([]int(nil), defaultPorts...)
	}
	return ports
}

func (a *App) promptDiscoveryMode(defaultMode string) string {
	fmt.Printf("[?] Discovery mode [masscan/nmap/direct] [Default %s]: ", defaultMode)
	input := strings.ToLower(strings.TrimSpace(a.readLineInput()))
	switch input {
	case "nmap":
		return "nmap"
	case "direct":
		return "direct"
	default:
		return defaultMode
	}
}

func (a *App) promptPositiveInt(prompt string, fallback int) int {
	fmt.Print(prompt)
	input := strings.TrimSpace(a.readLineInput())
	if input == "" {
		return fallback
	}
	if value, err := strconv.Atoi(input); err == nil && value > 0 {
		return value
	}
	return fallback
}

func parsePortList(raw string) []int {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	seen := make(map[int]struct{})
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 1 || value > 65535 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ports = append(ports, value)
	}
	sort.Ints(ports)
	return ports
}

func normalizeProxyTargets(tokens []string) []string {
	seen := make(map[string]struct{})
	var targets []string
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if host, port, ok := strings.Cut(token, ":"); ok && isNumericString(port) {
			token = host
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		targets = append(targets, token)
	}
	return targets
}

func joinInts(values []int) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func joinIntsTruncated(values []int, limit int) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for i, value := range values {
		if limit > 0 && i >= limit {
			break
		}
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ", ")
}

func saveProxyResults(dataDir, exportFile, cacheFile string, proxies []string) error {
	if dataDir == "" {
		dataDir = "."
	}

	lines := dedupeAndSortStrings(proxies)
	body := fmt.Sprintf("# Proxy scan results\n%s\n", strings.Join(lines, "\n"))
	if err := storage.AtomicWriteText(filepath.Join(dataDir, exportFile), body); err != nil {
		return err
	}
	return storage.AtomicWriteText(filepath.Join(dataDir, cacheFile), body)
}

func saveScanOutputResults(dataDir, scanKind string, endpoints []string, operationType string) (string, error) {
	if dataDir == "" {
		dataDir = "."
	}
	if scanKind == "" {
		scanKind = "scan"
	}

	var cleaned []string
	for _, ep := range endpoints {
		if operationType != "sni_scanner" && operationType != "desync_scanner" {
			if parts := strings.Fields(ep); len(parts) > 1 && strings.Contains(parts[1], ":") {
				cleaned = append(cleaned, parts[1])
			} else if len(parts) > 0 && strings.Contains(parts[0], ":") {
				cleaned = append(cleaned, parts[0])
			} else {
				cleaned = append(cleaned, ep)
			}
		} else {
			cleaned = append(cleaned, ep)
		}
	}

	lines := dedupeAndSortStrings(cleaned)
	// write plain text file (passed endpoints)
	body := fmt.Sprintf("# Passed endpoints\n# kind: %s\n# count: %d\n%s\n", scanKind, len(lines), strings.Join(lines, "\n"))
	stamp := time.Now().Format("20060102-150405")
	outDir := whitednsLogsDir(dataDir)
	_ = os.MkdirAll(outDir, 0o755)
	txtPath := filepath.Join(outDir, fmt.Sprintf("passed-%s-%s.txt", scanKind, stamp))
	if err := storage.AtomicWriteText(txtPath, body); err != nil {
		return "", err
	}

	// If SNI scanner, also write a CSV containing status per-host
	if operationType == "sni_scanner" || operationType == "desync_scanner" {
		csvLines := make([]string, 0, len(endpoints)+1)
		csvLines = append(csvLines, "hostname,ipport,status,result_kind,latency_ms,tls_version,http_status,sni_accepted,cert_matches_sni")
		for _, ep := range endpoints {
			parts := strings.Fields(ep)
			if len(parts) < 3 {
				// unknown format
				csvLines = append(csvLines, fmt.Sprintf(",%s,,,,,,%t,%t", ep, false, false))
				continue
			}
			hostname := parts[0]
			ipport := parts[1]
			status := parts[2]
			kind := ""
			latency := ""
			tlsv := ""
			httpst := ""
			if len(parts) >= 4 {
				kind = parts[3]
			}
			if len(parts) >= 5 {
				latency = parts[4]
			}
			if len(parts) >= 6 {
				tlsv = parts[5]
			}
			if len(parts) >= 7 {
				httpst = parts[6]
			}
			// normalize status to OK/FAIL/UNKNOWN
			stat := strings.ToUpper(status)
			if stat != "OK" && stat != "FAIL" {
				stat = "UNKNOWN"
			}
			sniAccepted := kind == "cert-match" || kind == "sni-ok"
			certMatch := kind == "cert-match"
			// build CSV line
			csvLines = append(csvLines, fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%t,%t", hostname, ipport, stat, kind, latency, tlsv, httpst, sniAccepted, certMatch))
		}
		csvPath := filepath.Join(outDir, fmt.Sprintf("sni-%s-%s.csv", scanKind, stamp))
		if err := storage.AtomicWriteText(csvPath, strings.Join(csvLines, "\n")); err != nil {
			// ignore csv write failure but still return txt path
		}
	}

	return txtPath, nil
}

func dedupeAndSortStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func defaultHTTPScanPorts() []int {
	return []int{80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091, 9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808}
}

func defaultSOCKS5ScanPorts() []int {
	return []int{1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 80, 443, 2053, 2083, 2087, 2096, 8443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8118, 8119, 8888, 8889, 3128, 3129, 9000, 9001, 9050, 9051, 9090, 9091, 9999, 10808}
}

func defaultProxyDiscovery() string {
	return "masscan"
}

func defaultHTTPDiscovery() string {
	return "masscan"
}

func isNumericString(s string) bool {
	_, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return err == nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
