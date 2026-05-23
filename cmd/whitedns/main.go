package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/bridge"
	"whitedns-go/internal/config"
	"whitedns-go/internal/proxy"
	"whitedns-go/internal/router"
	"whitedns-go/internal/rules"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/storage"
	"whitedns-go/internal/ui"
)

// syncWriter wraps an *os.File and forces a Sync after each Write
type syncWriter struct{ f *os.File }

func (w syncWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if err == nil {
		_ = w.f.Sync()
	}
	return n, err
}

func main() {
	cfg := config.Load()
	mode, host, port := parseFlags(cfg)
	cfg.ProxyHost = host
	cfg.ProxyPort = port

	// Initialize bundled nmap early so Python can access it
	if nmapPath, err := bridge.InitializeNmap(); err != nil {
		log.Printf("[!] Warning: Failed to initialize bundled nmap: %v", err)
	} else {
		log.Printf("[+] Bundled nmap initialized at: %s", nmapPath)
	}

	dataDir := initStorage()
	if mode == "proxy" {
		runProxy(cfg)
		return
	}

	app := mustBuildApp(cfg, dataDir)
	if err := app.RunTUI(); err != nil {
		log.Fatalf("TUI failed: %v", err)
	}
}

func parseFlags(cfg config.Config) (string, string, int) {
	mode := flag.String("mode", "ui", "run mode: ui or proxy")
	host := flag.String("host", cfg.ProxyHost, "listen host")
	port := flag.Int("port", cfg.ProxyPort, "listen port")
	flag.Parse()
	return *mode, *host, *port
}

func initStorage() string {
	dataDir := filepath.Join(os.Getenv("HOME"), ".whitedns")
	if err := storage.InitPaths(dataDir); err != nil {
		log.Printf("[!] Warning: Failed to init storage: %v", err)
	}
	return dataDir
}

func runProxy(cfg config.Config) {
	server := &proxy.Server{Addr: cfg.ListenAddr()}
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func mustBuildApp(cfg config.Config, dataDir string) *ui.App {
	scannerInst, routerInst, asnEngine, ruleEngine := buildServices(dataDir)
	projectRoot, goPortRoot := detectRoots()

	return &ui.App{
		Cfg:          cfg,
		Scanner:      scannerInst,
		Router:       routerInst,
		ASNEngine:    asnEngine,
		RuleEngine:   ruleEngine,
		DataDir:      dataDir,
		PythonBridge: bridge.New(projectRoot, goPortRoot),
	}
}

func buildServices(dataDir string) (*scanner.Scanner, *router.Router, *asn.ASNEngine, *rules.RuleEngine) {
	scannerInst := scanner.NewScanner(defaultScannerConfig())
	routerInst := router.NewRouter(defaultRouterConfig())
	asnEngine := asn.NewASNEngine(dataDir)
	ruleEngine := rules.NewRuleEngine()

	// Initialize a single shared log file for the whole app (real-time flushed)
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("[!] Warning: Could not create logs directory: %v", err)
	} else {
		logFilePath := filepath.Join(logDir, fmt.Sprintf("whitedns_%s.log", time.Now().Format("2006-01-02_15-04-05")))
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("[!] Warning: Could not open shared log file: %v", err)
		} else {
			// Attach writer that syncs after each write for real-time flushing
			log.SetOutput(syncWriter{f})

			// Attach the same file to the scanner (scanner will not close it)
			if err := scannerInst.InitFileLoggingWithFile(f); err != nil {
				log.Printf("[!] Warning: Could not attach scanner logging to shared file: %v", err)
			} else {
				log.Printf("[+] Shared logging initialized: %s", logFilePath)
			}
		}
	}

	if err := asnEngine.Load(); err != nil {
		log.Printf("[!] Warning: Could not load ASN data: %v", err)
	}

	routesFile := filepath.Join(dataDir, "white_routes.txt")
	if count, err := routerInst.LoadRoutes(routesFile); err == nil {
		log.Printf("[+] Loaded %d cached routes from disk", count)
	}

	return scannerInst, routerInst, asnEngine, ruleEngine
}

func defaultScannerConfig() *scanner.ScannerConfig {
	return &scanner.ScannerConfig{
		ProbeTimeout:        2500 * time.Millisecond,
		ProbeRetries:        2,
		MaxConcurrentProbes: 4,
		ProbeIntervalMs:     100,
		MasscanRate:         1000,
		MasscanRetries:      2,
		MasscanWaitSec:      10,
		NmapTiming:          "-T4",
		NmapRetries:         2,
		TargetPorts:         []int{443, 2053, 2083, 2087, 2096, 8443},
	}
}

func defaultRouterConfig() *router.RouterConfig {
	return &router.RouterConfig{
		L1CacheTTLMs:           30000,
		L2CacheTTLMs:           300000,
		HistoryTTLSec:          60,
		RaceMaxConcurrency:     4,
		RaceTimeoutMs:          8000,
		FailureQuarantineSec:   600,
		MaxPrimaryCandidates:   12,
		MaxSecondaryCandidates: 6,
	}
}

func detectRoots() (string, string) {
	wd, err := os.Getwd()
	if err != nil {
		return ".", "."
	}
	goPortRoot := wd
	if filepath.Base(wd) != "go-port" {
		candidate := filepath.Join(wd, "go-port")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			goPortRoot = candidate
		}
	}
	projectRoot := filepath.Dir(goPortRoot)
	return projectRoot, goPortRoot
}
