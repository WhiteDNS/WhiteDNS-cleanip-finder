package ui

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"whitedns-go/internal/bundledata"
	"whitedns-go/internal/config"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/storage"
	"whitedns-go/internal/tlsprobe"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func hexToRGB(hex string) (int, int, int) {
	hex = strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(hex) != 6 {
		return 255, 255, 255
	}
	var r, g, b int
	fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b)
	return r, g, b
}

func lerpHexColor(c1, c2 string, t float64) string {
	r1, g1, b1 := hexToRGB(c1)
	r2, g2, b2 := hexToRGB(c2)
	ri := int(float64(r1) + (float64(r2)-float64(r1))*t)
	gi := int(float64(g1) + (float64(g2)-float64(g1))*t)
	bi := int(float64(b1) + (float64(b2)-float64(b1))*t)
	return fmt.Sprintf("#%02x%02x%02x", ri, gi, bi)
}

func renderGradientText(text string, colors []string, bold bool) string {
	if text == "" {
		return ""
	}
	if len(colors) == 0 {
		colors = []string{"#ffffff"}
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return ""
	}
	if len(colors) == 1 {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(colors[0]))
		if bold {
			style = style.Bold(true)
		}
		return style.Render(text)
	}
	var out strings.Builder
	for i, r := range runes {
		var color string
		if len(runes) == 1 {
			color = colors[0]
		} else {
			position := float64(i) / float64(len(runes)-1)
			segment := position * float64(len(colors)-1)
			left := int(math.Floor(segment))
			if left >= len(colors)-1 {
				left = len(colors) - 2
			}
			if left < 0 {
				left = 0
			}
			color = lerpHexColor(colors[left], colors[left+1], segment-float64(left))
		}
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
		if bold {
			style = style.Bold(true)
		}
		out.WriteString(style.Render(string(r)))
	}
	return out.String()
}

func renderMenuTitle(width int, logs int) string {
	if width < 20 {
		width = 20
	}
	brandColors := []string{"#00d1ff", "#00d1ff", "#00c8f0", "#ff2d20", "#ff7a00", "#f5c400"}
	devColors := []string{"#00d1ff", "#00c8f0", "#ff7a00", "#f5c400"}
	meta := sDim.Render(fmt.Sprintf("logs:%d  %s", logs, time.Now().Format("15:04:05")))

	if width < 72 {
		line := renderGradientText("WHITEDNS v1.2", brandColors, true)
		credit := renderGradientText("developed by TAjirax", devColors, false)
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, line) + "\n" +
			lipgloss.PlaceHorizontal(width, lipgloss.Center, credit) + "\n" +
			lipgloss.PlaceHorizontal(width, lipgloss.Center, meta)
	}

	banner := []string{
		"__        ___   _ ___ _____ _____ ____  _   _ ____",
		"\\ \\      / / | | |_ _|_   _| ____|  _ \\| \\ | / ___|",
		" \\ \\ /\\ / /| |_| || |  | | |  _| | | | |  \\| \\___ \\",
		"  \\ V  V / |  _  || |  | | | |___| |_| | |\\  |___) |",
		"   \\_/\\_/  |_| |_|___| |_| |_____|____/|_| \\_|____/",
	}

	blockWidth := 0
	for _, line := range banner {
		if lineWidth := lipgloss.Width(line); lineWidth > blockWidth {
			blockWidth = lineWidth
		}
	}
	var out strings.Builder
	for _, line := range banner {
		if pad := blockWidth - lipgloss.Width(line); pad > 0 {
			line += strings.Repeat(" ", pad)
		}
		out.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, renderGradientText(line, brandColors, true)))
		out.WriteString("\n")
	}
	tagline := renderGradientText("v1.2  -  developed by TAjirax", devColors, true)
	out.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, tagline))
	out.WriteString("\n")
	out.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, meta))
	return out.String()
}

// ------------------------------------------------------------
//  Message types
// ------------------------------------------------------------
// Message types
// ------------------------------------------------------------

type scanStartedMsg struct{}
type scanProgressMsg struct {
	current   int
	total     int
	hits      int
	startTime time.Time
	currentIP string
	totalIPs  int
}
type scanCompleteMsg struct {
	proxies  []string
	err      error
	duration time.Duration
}
type poolOperationCompleteMsg struct {
	operationType string
	results       []string
	err           error
	duration      time.Duration
}
type actionCompleteMsg struct {
	title string
	text  string
	err   error
}
type errorMsg struct{ text string }
type logMsg struct{ text string }

// ------------------------------------------------------------
//  Screen identifiers
// ------------------------------------------------------------
// Screen identifiers
// ------------------------------------------------------------

const (
	screenMenu              = "menu"
	screenScanMode          = "scan_mode"
	screenSelectASN         = "select_asn"
	screenTypeTargets       = "type_targets"
	screenReviewTargets     = "review_targets"
	screenSelectPorts       = "select_ports"
	screenSelectMethod      = "select_scan_method"
	screenSelectTransfer    = "select_transfer_mode"
	screenSelectConcurrency = "select_concurrency"
	screenScanning          = "scanning"
	screenEditDPITarget     = "edit_dpi_target"
	screenManageDPISettings = "manage_dpi_settings"
	screenManageTLSProbe    = "manage_tls_probe"
	screenToggleProbeFlags  = "toggle_probe_flags"
	screenInspectIP         = "inspect_ip"
	screenReloadPool        = "reload_pool"
	screenScanResults       = "scan_results"
	screenSNISource         = "sni_source"
	screenSNIMode           = "sni_mode"
)

const maxAllowedConcurrency = 10000

// ------------------------------------------------------------
//  Data types
// ------------------------------------------------------------
// Data types
// ------------------------------------------------------------

type asnEntry struct {
	Networks []string // All networks/CIDRs for this ASN
	ASN      string
	ASName   string
	Type     string
	ASDomain string
}

type scanConfig struct {
	Mode                      string
	Targets                   []string
	ASNs                      []string
	Ports                     []int
	PortsString               string
	Method                    string
	TransferModel             string
	FilterType                string
	Concurrency               int
	AdaptiveDomainConcurrency int
	// LowBandwidth widens verification timeouts for users on slow / high-latency
	// links (e.g. 8 Mbps down, 1 Mbps up) so good endpoints are not falsely
	// timed out by the default short windows.
	LowBandwidth bool
	// SNIDomains overrides the SNI hostnames probed by the SNI scanner. When
	// empty the scanner falls back to the built-in + managed default list.
	SNIDomains []string
	// SNIStrict requires the TLS handshake to accept the presented SNI before a
	// pair is counted (for domain-fronting / SNI-spoofing discovery).
	SNIStrict bool
}

type menuItem struct {
	key    string
	label  string
	action string
}

type portPreset struct {
	label string
	ports string
}

// ------------------------------------------------------------
//  Colour palette  (256-colour, works everywhere)
// ------------------------------------------------------------

var (
	// Base colours
	cBase    = lipgloss.Color("235") // near-black bg
	cSurface = lipgloss.Color("237") // panel bg
	cMuted   = lipgloss.Color("241") // dim text
	cText    = lipgloss.Color("252") // normal text
	cBright  = lipgloss.Color("255") // bright white

	// Accent colours
	cAccent  = lipgloss.Color("39")  // sky blue - primary accent
	cGreen   = lipgloss.Color("77")  // mint green
	cYellow  = lipgloss.Color("220") // amber
	cOrange  = lipgloss.Color("214") // orange
	cRed     = lipgloss.Color("203") // coral red
	cPurple  = lipgloss.Color("141") // lavender
	cMagenta = lipgloss.Color("205") // hot pink

	// Border colours
	cBorderNormal = lipgloss.Color("238")
	cBorderActive = lipgloss.Color("39")
	cBorderAlt    = lipgloss.Color("141")

	// Composed styles

	sTitle = lipgloss.NewStyle().
		Bold(true).Foreground(cMagenta)

	sHeader = lipgloss.NewStyle().
		Bold(true).Foreground(cBright).Background(cAccent).
		PaddingLeft(1).PaddingRight(1)

	sDim = lipgloss.NewStyle().Foreground(cMuted)

	sSelected = lipgloss.NewStyle().
			Bold(true).Foreground(cBase).Background(cPurple).
			PaddingLeft(1).PaddingRight(1)

	sNormal = lipgloss.NewStyle().Foreground(cBright).PaddingLeft(2)

	sSuccess = lipgloss.NewStyle().Bold(true).Foreground(cGreen)
	sError   = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	sWarn    = lipgloss.NewStyle().Bold(true).Foreground(cOrange)
	sInfo    = lipgloss.NewStyle().Foreground(cAccent)
	sAccent  = lipgloss.NewStyle().Bold(true).Foreground(cYellow)
	sPurple  = lipgloss.NewStyle().Foreground(cPurple)
	sItem    = lipgloss.NewStyle().Foreground(cBright).PaddingLeft(1) // Changed to white for ASN text

	// Panels
	panelStyle = func(borderColor lipgloss.Color) lipgloss.Style {
		return lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(0, 1)
	}
)

// ------------------------------------------------------------
//  Model
// ------------------------------------------------------------

type tuiModel struct {
	app    *App
	width  int
	height int

	screen        string
	prevScreen    string
	screenChanged bool // track if screen changed for selective clearing
	cursor        int

	menu    []menuItem
	ti      textinput.Model
	spinner spinner.Model
	vp      viewport.Model // for scrollable result lists

	tiStep                int
	logs                  []string
	operationType         string
	toast                 string
	toastExpiry           time.Time
	stepData              map[string]string
	configMakerStage      string
	configMakerFlow       string
	configMakerSourceMode string
	configMakerTargetMode string
	configMakerConfigText string
	configMakerTargetText string
	configMakerOutputPath string
	configMakerMessage    string
	configMakerPreview    []string
	scanConfig            scanConfig
	menuCol               int
	menuRow               int
	dpiState              dpiState

	asnList     []asnEntry
	asnFiltered []asnEntry

	portPresets        []portPreset
	methodOptions      []string
	transferOptions    []string
	concurrencyOptions []string
	selectedItems      map[int]bool
	scanKind           string

	scanStartTime   time.Time
	scanProgress    int
	scanTotal       int
	scanHits        int
	scanResults     []string
	scanErr         error
	scanMsgCh       chan tea.Msg
	scanCurrentIP   string
	scanTotalIPs    int
	scanLogPath     string
	scanLogMu       *sync.Mutex
	scanPaused      bool
	scanCtx         context.Context
	scanCancel      context.CancelFunc
	transferLogPath string
	transferLogMu   *sync.Mutex
	// incremental scan output file (written as results are discovered)
	scanOutputPath        string
	scanFailedPath        string
	scanCSVPath           string
	scanDomainPassPath    string
	scanOutputWritten     map[string]bool
	scanDomainPassWritten map[string]bool
	scanOutputMu          *sync.Mutex
	// pasteConfirm: used to avoid immediate submission when pasting multi-line targets
	pasteConfirm   bool
	pasteConfirmAt time.Time
	// lastEnterTime: track when last Enter was pressed to detect paste-generated Enters
	lastEnterTime time.Time
	// pasteBuffer accumulates terminal bracketed-paste content (incl. newlines)
	// so multi-line target pastes work without relying on an OS clipboard tool
	// (xclip/xsel), which many Linux/Termux/SSH users do not have installed.
	pasteBuffer string
	// parsed target review state
	parsedTargetStats   *scanner.ParseTargetStats
	parsedTargetsScroll int
	// typingEnabled controls whether keys are routed into the ASN search box.
	typingEnabled bool
}

// ------------------------------------------------------------
//  Constructor
// ------------------------------------------------------------

func NewTUI(a *App) *tuiModel {
	ti := textinput.New()
	ti.CharLimit = 1024
	ti.Width = 60

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(cYellow)

	menu := []menuItem{
		{key: "1", label: "Scan IPs", action: "scan_ips"},
		{key: "2", label: "Scan HTTP Proxies", action: "scan"},
		{key: "3", label: "Scan SOCKS5 Proxies", action: "scan_socks5"},
		{key: "4", label: "SNI Scanner (TLS Hostname Probe)", action: "sni_scanner"},
		{key: "5", label: "Reload IP Pool", action: "reload_pool"},
		{key: "6", label: "Manage IP Pool", action: "manage_pool"},
		{key: "7", label: "Inspect IPs (ASN)", action: "inspect_ip"},
		{key: "8", label: "Export ASN IPs", action: "export_asn"},
		{key: "9", label: "Autotune Scan Rates", action: "autotune"},
		{key: "10", label: "Desync Scanner", action: "desync_scanner"},
		{key: "11", label: "Manage SNI Probe Domains", action: "manage_tls_probe"},
		{key: "12", label: "Settings: Probe Heuristics", action: "toggle_probe_flags"},
		{key: "13", label: "Config Maker", action: "config_maker"},
		{key: "14", label: "Configure Desync", action: "configure_desync"},
		{key: "15", label: "Clear Cache", action: "clear_cache"},
		{key: "0", label: "Exit", action: "exit"},
	}

	m := &tuiModel{
		app:                   a,
		width:                 80,
		height:                24,
		screen:                screenMenu,
		menu:                  menu,
		ti:                    ti,
		spinner:               sp,
		logs:                  []string{},
		operationType:         "scan",
		stepData:              make(map[string]string),
		configMakerOutputPath: "",
		scanConfig:            scanConfig{Concurrency: 250, TransferModel: "old"},
		portPresets: []portPreset{
			{label: "80 - HTTP only", ports: "80"},
			{label: "443 - HTTPS only", ports: "443"},
			{label: "443,2053,2083,2087,2096,8443 - Cloudflare TLS", ports: "443,2053,2083,2087,2096,8443"},
			{label: "80,443,2053,2083,2087,2096,8443 - Cloudflare HTTP/TLS", ports: "80,443,2053,2083,2087,2096,8443"},
			{label: "80,443 - HTTP/HTTPS", ports: "80,443"},
			{label: "80,443,8080 - Most common", ports: "80,443,8080"},
			{label: "80,8080,3128 - HTTP proxies", ports: "80,8080,3128"},
			{label: "443,8443 - HTTPS ports", ports: "443,8443"},
			{label: "8000-8100 - Dev range", ports: "8000-8100"},
			{label: "8080-8090 - Proxy range", ports: "8080-8090"},
			{label: "3000-3500 - App servers", ports: "3000-3500"},
			{label: "9000-9100 - Services", ports: "9000-9100"},
			{label: "1080-1090 - SOCKS", ports: "1080-1090"},
			{label: "8000,8001,8008,8080,8888 - Extended HTTP", ports: "8000,8001,8008,8080,8888"},
			{label: "80,443,3128,8080,8118 - Scan preset", ports: "80,443,3128,8080,8118"},
			{label: "80,443,2053,2083,2087,2096,8443 - Cloudflare scan", ports: "80,443,2053,2083,2087,2096,8443"},
			{label: "80,443,3128,8000,8080,8888,8118,9000,9050,1080 - All common", ports: "80,443,3128,8000,8080,8888,8118,9000,9050,1080"},
			{label: "1080-1090,3128,8080,8118,9050-9051 - Full SOCKS", ports: "1080-1090,3128,8080,8118,9050-9051"},
			{label: "Custom - Type ports manually", ports: ""},
		},
		methodOptions:      []string{"Direct (fast, in-process)", "Masscan preflight", "Nmap preflight"},
		transferOptions:    []string{"Old transfer model (stable)", "goBrrrr transfer mode (fast)"},
		concurrencyOptions: []string{"Low Bandwidth (50, long timeout)", "Low (50)", "Medium (250)", "High (500)", "Very High (1000)", "Max (2000)", "Extreme (5000)"},
		selectedItems:      make(map[int]bool),
		scanKind:           "http",
		typingEnabled:      true,
		menuCol:            0,
		menuRow:            0,
		dpiState:           loadDPIState(a.DataDir),
	}

	// prepare incremental output tracking
	m.scanOutputWritten = make(map[string]bool)
	m.scanDomainPassWritten = make(map[string]bool)
	m.scanLogMu = &sync.Mutex{}
	m.transferLogMu = &sync.Mutex{}
	m.scanOutputMu = &sync.Mutex{}

	m.loadASNFile()
	return m
}

// ------------------------------------------------------------
//  ASN loader
// ------------------------------------------------------------

func (m *tuiModel) loadASNFile() {
	var r *bufio.Reader
	asnData, bundleErr := bundledata.ASNIPv4CSV()
	if bundleErr == nil {
		r = bufio.NewReader(bytes.NewReader(asnData))
	} else {
		asnFile := resolveASNCSVPath(m.app.DataDir)
		f, err := os.Open(asnFile)
		if err != nil {
			m.addLog(fmt.Sprintf("Warning: could not load ASN file: %v", err))
			return
		}
		defer f.Close()
		r = bufio.NewReader(f)
	}
	parseLine := func(line string) ([]string, error) {
		line = strings.TrimSpace(line)
		if line == "" {
			return nil, nil
		}
		lineReader := csv.NewReader(strings.NewReader(line))
		lineReader.FieldsPerRecord = -1
		lineReader.LazyQuotes = true
		return lineReader.Read()
	}

	// Group networks by ASN
	asnMap := make(map[string]*asnEntry)
	lineNo := 0
	for {
		line, readErr := r.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			if len(line) == 0 {
				m.addLog(fmt.Sprintf("Warning: could not read ASN file: %v", readErr))
				return
			}
		}
		if readErr == io.EOF && len(line) == 0 {
			break
		}

		lineNo++
		if lineNo == 1 {
			if readErr == io.EOF {
				break
			}
			continue
		}

		rec, err := parseLine(strings.TrimRight(line, "\r\n"))
		if err != nil || len(rec) < 9 {
			if readErr == io.EOF {
				break
			}
			continue
		}
		asn := rec[5]
		network := rec[0]

		if _, exists := asnMap[asn]; !exists {
			asnMap[asn] = &asnEntry{
				ASN:      asn,
				ASName:   rec[6],
				ASDomain: rec[7],
				Type:     rec[8],
				Networks: []string{},
			}
		}
		asnMap[asn].Networks = append(asnMap[asn].Networks, network)

		if readErr == io.EOF {
			break
		}
	}

	// Convert to sorted list
	for _, entry := range asnMap {
		sort.Strings(entry.Networks) // Sort networks within each ASN
		m.asnList = append(m.asnList, *entry)
	}
	sort.Slice(m.asnList, func(i, j int) bool { return m.asnList[i].ASN < m.asnList[j].ASN })
	m.asnFiltered = m.asnList
}

func resolveASNCSVPath(dataDir string) string {
	// Build a list of roots to probe. We attempt dataDir, its parent,
	// the executable directory, the working directory, and then walk
	// upwards from those roots a few levels to handle installs where
	// the data files are placed beside the executable or in a repo
	// parent directory.
	var roots []string
	pushRoot := func(r string) {
		if r == "" {
			return
		}
		roots = append(roots, r)
	}

	pushRoot(dataDir)
	pushRoot(filepath.Dir(dataDir))
	if exePath, err := os.Executable(); err == nil {
		pushRoot(filepath.Dir(exePath))
	}
	if wd, err := os.Getwd(); err == nil {
		pushRoot(wd)
	}

	// Also include the repository root (two levels up from this source file)
	// in case running from tree during development.
	if srcRoot := filepath.Join(filepath.Dir("."), ".."); srcRoot != "" {
		pushRoot(srcRoot)
	}

	// For each root, probe that root and up to 4 parent levels for IranASNs
	// folder containing filtered_ipv4.csv.
	probed := make(map[string]struct{})
	for _, root := range roots {
		cur := filepath.Clean(root)
		for i := 0; i < 5; i++ {
			candidate := filepath.Join(cur, "IranASNs", "filtered_ipv4.csv")
			if _, ok := probed[candidate]; !ok {
				probed[candidate] = struct{}{}
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
			}
			parent := filepath.Dir(cur)
			if parent == cur || parent == "." || parent == string(filepath.Separator) {
				break
			}
			cur = parent
		}
	}

	// Last-resort: try the file next to dataDir even if it doesn't exist; this
	// keeps previous behavior for callers expecting a path.
	if dataDir != "" {
		return filepath.Join(filepath.Dir(dataDir), "IranASNs", "filtered_ipv4.csv")
	}
	// Fallback to known relative path in repository root
	return filepath.Join("..", "IranASNs", "filtered_ipv4.csv")
}

// ------------------------------------------------------------
//  Init
// ------------------------------------------------------------

func (m tuiModel) Init() tea.Cmd { return m.spinner.Tick }

// ------------------------------------------------------------
//  Update  (single dispatch)
// ------------------------------------------------------------

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// Window resize
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = ws.Width
		m.height = ws.Height
		m.vp.Width = ws.Width - 4
		m.vp.Height = ws.Height - 10
		return m, nil
	}

	// Global keys
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			// Config maker manages its own step-by-step back navigation on
			// Esc (so Esc steps back one screen instead of exiting the
			// whole flow); let it through to the screen handler below.
			if m.screen != screenMenu && m.screen != screenConfigMaker {
				m.goBack()
				m.ti.Blur()
				return m, nil
			}
		}
	}

	// Completion messages
	switch v := msg.(type) {
	case scanCompleteMsg:
		return m.handleScanComplete(v)
	case scanProgressMsg:
		if v.total > 0 {
			m.scanTotal = v.total
		}
		prevHits := m.scanHits
		m.scanProgress = v.current
		m.scanHits = v.hits
		if m.scanStartTime.IsZero() {
			m.scanStartTime = v.startTime
		}
		m.scanCurrentIP = v.currentIP
		m.scanTotalIPs = v.totalIPs
		m.writeScanLogLine(fmt.Sprintf("[PROGRESS] processed=%d/%d hits=%d current=%s totalIPs=%d", v.current, v.total, v.hits, v.currentIP, v.totalIPs))
		if v.currentIP != "" {
			if m.operationType == "sni_scanner" {
				// v.currentIP contains the full result string for SNI
				if strings.Contains(v.currentIP, " OK ") {
					if len(m.scanResults) == 0 || m.scanResults[len(m.scanResults)-1] != v.currentIP {
						m.scanResults = append(m.scanResults, v.currentIP)
					}
				}
			} else if m.operationType != "scan_ips" && v.hits > prevHits {
				// For scan_ips, currentIP is whichever endpoint a worker happened to
				// finish when this throttled progress tick fired, not necessarily the
				// one that just got accepted (probes run concurrently). Recording it
				// here would pollute scanResults with non-accepted endpoints; the
				// real accepted IP is captured from [ACCEPT] log lines instead via
				// appendDomainPassLineFromScanLog.
				if len(m.scanResults) == 0 || m.scanResults[len(m.scanResults)-1] != v.currentIP {
					m.scanResults = append(m.scanResults, v.currentIP)
				}
			}
		}
		// Re-arm wait for next message so UI keeps consuming from the channel
		if m.scanMsgCh != nil {
			return m, waitForScanMessage(m.scanMsgCh)
		}
		return m, nil
	case poolOperationCompleteMsg:
		return m.handlePoolOperationComplete(v)
	case actionCompleteMsg:
		return m.handleActionComplete(v)
	case errorMsg:
		m.setToast(sError.Render("x "+v.text), 5*time.Second)
		return m, nil
	case logMsg:
		m.appendTransferLogLineFromScanLog(v.text)
		m.appendDomainPassLineFromScanLog(v.text)
		m.addLog(v.text)
		// Re-arm wait for next message so UI keeps consuming from the channel
		if m.scanMsgCh != nil {
			return m, waitForScanMessage(m.scanMsgCh)
		}
		return m, nil
	}

	// Spinner tick
	if _, ok := msg.(spinner.TickMsg); ok {
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	// Screen-specific update-
	var screenCmd tea.Cmd
	switch m.screen {
	case screenMenu:
		m, screenCmd = m.handleMenuScreen(msg)
	case screenScanMode:
		m, screenCmd = m.handleScanModeScreen(msg)
	case screenSNISource:
		m, screenCmd = m.handleSNISourceScreen(msg)
	case screenSNIMode:
		m, screenCmd = m.handleSNIModeScreen(msg)
	case screenSelectASN:
		m, screenCmd = m.handleSelectASNScreen(msg)
	case screenTypeTargets:
		m, screenCmd = m.handleTypeTargetsScreen(msg)
	case screenReviewTargets:
		m, screenCmd = m.handleReviewTargetsScreen(msg)
	case screenSelectPorts:
		m, screenCmd = m.handleSelectPortsScreen(msg)
	case screenSelectMethod:
		m, screenCmd = m.handleSelectMethodScreen(msg)
	case screenSelectTransfer:
		m, screenCmd = m.handleSelectTransferScreen(msg)
	case screenSelectConcurrency:
		m, screenCmd = m.handleSelectConcurrencyScreen(msg)
	case screenScanning:
		m, screenCmd = m.handleScanningScreen(msg)
	case screenConfigMaker:
		m, screenCmd = m.handleConfigMakerScreen(msg)
	case screenEditDPITarget:
		m, screenCmd = m.handleEditDPITargetScreen(msg)
	case screenManageDPISettings:
		m, screenCmd = m.handleManageDPISettingsScreen(msg)
	case screenManageTLSProbe:
		m, screenCmd = m.handleManageTLSProbeScreen(msg)
	case screenToggleProbeFlags:
		m, screenCmd = m.handleToggleProbeFlagsScreen(msg)
	case screenInspectIP:
		m, screenCmd = m.handleInspectIPScreen(msg)
	case screenScanResults:
		m, screenCmd = m.handleScanResultsScreen(msg)
	}
	if screenCmd != nil {
		cmds = append(cmds, screenCmd)
	}

	return m, tea.Batch(cmds...)
}

// ------------------------------------------------------------
//  View  - single full-terminal render
// ------------------------------------------------------------

func (m tuiModel) View() string {
	w, h := m.width, m.height
	if w < 40 {
		w = 40
	}
	if h < 10 {
		h = 10
	}

	var body string
	switch m.screen {
	case screenMenu:
		body = m.viewMenu(w, h)
	case screenScanMode:
		body = m.viewScanMode(w, h)
	case screenSNISource:
		body = m.viewSNISource(w, h)
	case screenSNIMode:
		body = m.viewSNIMode(w, h)
	case screenSelectASN:
		body = m.viewSelectASN(w, h)
	case screenTypeTargets:
		body = m.viewTypeTargets(w, h)
	case screenReviewTargets:
		body = m.viewReviewTargets(w, h)
	case screenSelectPorts:
		body = m.viewSelectPorts(w, h)
	case screenSelectMethod:
		body = m.viewSelectMethod(w, h)
	case screenSelectTransfer:
		body = m.viewSelectTransfer(w, h)
	case screenSelectConcurrency:
		body = m.viewSelectConcurrency(w, h)
	case screenScanning:
		body = m.viewScanning(w, h)
	case screenScanResults:
		body = m.viewScanResults(w, h)
	case screenConfigMaker:
		body = m.viewConfigMaker(w, h)
	case screenManageDPISettings:
		body = m.viewManageDPISettings(w, h)
	case screenToggleProbeFlags:
		body = m.viewToggleProbeFlags(w, h)
	case screenEditDPITarget:
		body = m.viewEditDPITarget(w, h)
	case screenManageTLSProbe:
		body = m.viewManageTLSProbe(w, h)
	case screenInspectIP:
		body = m.viewSimpleInput(w, h, "Inspect IP", "Enter IP address")
	default:
		body = m.viewMenu(w, h)
	}

	// Full-frame paint: fill every row and column to prevent stale stacked content
	// while preserving each line's existing lipgloss styles and colours.
	blank := strings.Repeat(" ", w)
	lines := strings.Split(body, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	out := make([]string, 0, h)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			out = append(out, blank)
			continue
		}
		lineWidth := lipgloss.Width(line)
		if lineWidth < w {
			line = line + strings.Repeat(" ", w-lineWidth)
		} else if lineWidth > w {
			line = lipgloss.NewStyle().MaxWidth(w).Render(line)
		}
		out = append(out, line)
	}
	for len(out) < h {
		out = append(out, blank)
	}
	return strings.Join(out, "\n")
}

// ------------------------------------------------------------
//  Screen renderers
// ------------------------------------------------------------

func (m tuiModel) viewMenu(w, h int) string {
	inner := w - 6 // account for panel border+padding
	half := (len(m.menu) + 1) / 2

	// Title bar
	titleBar := renderMenuTitle(inner, len(m.logs))
	accentWidth := w - 2
	if accentWidth < inner {
		accentWidth = inner
	}
	accentBar := lipgloss.NewStyle().Foreground(cAccent).Render(strings.Repeat("-", accentWidth))

	// Two-column menu
	colW := (inner - 4) / 2

	var col1, col2 []string
	for i, item := range m.menu {
		label := fmt.Sprintf("[%s] %s", item.key, item.label)
		if len(label) > colW-2 {
			label = label[:colW-3] + "..."
		}
		row := i
		col := 0
		if i >= half {
			col = 1
			row = i - half
		}
		rendered := lipgloss.NewStyle().Width(colW).Render(label)
		if col == m.menuCol && row == m.menuRow {
			rendered = sSelected.Width(colW).Render(label)
		} else {
			rendered = sNormal.Width(colW).Render(label)
		}
		if i < half {
			col1 = append(col1, rendered)
		} else {
			col2 = append(col2, rendered)
		}
	}
	// Equalize column lengths
	for len(col1) < len(col2) {
		col1 = append(col1, strings.Repeat(" ", colW))
	}
	for len(col2) < len(col1) {
		col2 = append(col2, strings.Repeat(" ", colW))
	}

	var menuRows strings.Builder
	for i := range col1 {
		menuRows.WriteString(col1[i] + "  " + col2[i] + "\n")
	}

	menuPanel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" COMMANDS ") + "\n\n" + menuRows.String(),
	)

	// Activity log
	logLines := m.recentLogs(5, inner-4)
	logContent := sHeader.Render(" ACTIVITY LOG ") + "\n"
	if len(logLines) == 0 {
		logContent += sDim.Render("  No activity yet")
	} else {
		logContent += strings.Join(logLines, "\n")
	}
	logPanel := panelStyle(cBorderAlt).Width(inner).Render(logContent)

	// Help bar (restore arrows/emojis)
	help := sDim.Render("↑↓ move column  ·  ←→ switch columns  ·  Enter select  ·  q quit")

	var out strings.Builder
	out.WriteString(titleBar + "\n")
	out.WriteString(accentBar + "\n\n")
	out.WriteString(menuPanel + "\n\n")
	out.WriteString(logPanel + "\n\n")
	if m.toastActive() {
		out.WriteString(m.toast + "\n")
	}
	out.WriteString(help)
	return out.String()
}

// Generic list screen helper

func (m tuiModel) viewList(w, h int, title string, items []string, help string) string {
	inner := w - 6
	visibleRows := h - 10
	if visibleRows < 3 {
		visibleRows = 3
	}

	// scroll window around cursor
	start := 0
	if m.cursor >= visibleRows {
		start = m.cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(items) {
		end = len(items)
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		if i == m.cursor {
			rows.WriteString(sSelected.Render(items[i]) + "\n")
		} else {
			rows.WriteString(sNormal.Render(items[i]) + "\n")
		}
	}
	if len(items) > visibleRows {
		rows.WriteString(sDim.Render(fmt.Sprintf("  [%d/%d]", m.cursor+1, len(items))) + "\n")
	}

	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" "+title+" ") + "\n\n" + rows.String(),
	)
	return panel + "\n\n" + sDim.Render(help)
}

func (m tuiModel) viewScanMode(w, h int) string {
	label := strings.ToUpper(m.scanKind)
	items := []string{
		"[list] 🔍 Select from IranASN file",
		"[paste] 📋 Paste targets (IPs/CIDRs)",
		"[type] ⌨️ Type targets manually",
	}
	return m.viewList(w, h,
		fmt.Sprintf("SCAN MODE - %s", label),
		items,
		"↑↓ navigate  ·  Enter select  ·  Esc back",
	)
}

func (m tuiModel) viewSNISource(w, h int) string {
	if m.tiStep == 1 {
		inner := w - 6
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" ENTER SNI DOMAIN(S) ") + "\n\n" +
				sInfo.Render("Type one or more domains (space, comma, or newline separated).\n\n") +
				"  " + m.ti.View(),
		)
		return panel + "\n\n" + sDim.Render("Enter to continue  ·  Esc back")
	}
	def := tlsprobe.GetDomains(m.app.DataDir)
	items := []string{
		fmt.Sprintf("Use default SNI list (%d domains)", len(def)),
		"Enter your own domain(s)",
	}
	return m.viewList(w, h, "SNI SOURCE", items, "↑↓ navigate  ·  Enter select  ·  Esc back")
}

func (m tuiModel) viewSelectASN(w, h int) string {
	inner := w - 6
	// Search bar always visible
	searchBar := "  " + sDim.Render("Search: ") + m.ti.View()

	visibleRows := h - 14
	if visibleRows < 3 {
		visibleRows = 3
	}

	start := 0
	if m.cursor >= visibleRows {
		start = m.cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(m.asnFiltered) {
		end = len(m.asnFiltered)
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		e := m.asnFiltered[i]
		checked := " "
		if m.selectedItems[i] {
			checked = "x"
		}
		line := fmt.Sprintf("[%s] %-12s  %s", checked, e.ASN, e.ASName)
		if len(line) > inner-4 {
			line = line[:inner-4]
		}
		if i == m.cursor {
			rows.WriteString(sSelected.Render(line) + "\n")
		} else {
			// Use bright white for ASN text as requested
			rows.WriteString(lipgloss.NewStyle().Foreground(cBright).PaddingLeft(1).Render(line) + "\n")
		}
	}

	status := fmt.Sprintf("  %s  selected: %s",
		sInfo.Render(fmt.Sprintf("%d available", len(m.asnFiltered))),
		sAccent.Render(fmt.Sprintf("%d", len(m.selectedItems))),
	)

	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" SELECT ASN NETWORKS ") + "\n\n" +
			searchBar + "\n\n" +
			rows.String() + "\n" +
			status,
	)
	helpText := "↑↓ navigate  ·  ; typing on/off  ·  TAB toggle  ·  Space toggle in selection mode  ·  /all select all  ·  Enter confirm  ·  Esc back"
	if m.operationType == "export_asn" {
		helpText = "↑↓ navigate  ·  ; typing on/off  ·  TAB toggle  ·  Space toggle in selection mode  ·  /all select all  ·  Enter export  ·  Esc back"
	}
	help := sDim.Render(helpText)
	return panel + "\n\n" + help
}

func (m tuiModel) viewTypeTargets(w, h int) string {
	inner := w - 6
	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" ENTER TARGETS ") + "\n\n" +
			sDim.Render("  IPs or CIDRs, space/newline separated\n\n") +
			"  " + m.ti.View(),
	)
	return panel + "\n\n" + sDim.Render("Enter confirm  ·  Esc back")
}

func (m tuiModel) viewReviewTargets(w, h int) string {
	if m.parsedTargetStats == nil || len(m.scanConfig.Targets) == 0 {
		return "Error: No targets to review"
	}

	stats := m.parsedTargetStats
	inner := w - 6
	contentHeight := h - 13

	// Build header with statistics
	header := sHeader.Render(" REVIEW TARGETS ")
	statsLine := fmt.Sprintf("Valid: %d  |  Invalid: %d  |  Total: %d",
		len(stats.Valid), len(stats.Invalid), stats.Total)
	statsDisplay := sAccent.Render(statsLine)

	// Build targets list with scrolling and better spacing
	var targetLines []string
	start := m.parsedTargetsScroll
	end := start + contentHeight - 4
	if end > len(m.scanConfig.Targets) {
		end = len(m.scanConfig.Targets)
	}

	// Add proper spacing between targets for readability
	for i := start; i < end; i++ {
		targetLines = append(targetLines, fmt.Sprintf("  %3d.  %s", i+1, m.scanConfig.Targets[i]))
	}

	// Join with extra line spacing for better readability
	targetList := strings.Join(targetLines, "\n")

	// Add scroll indicator
	if len(m.scanConfig.Targets) > end {
		remaining := len(m.scanConfig.Targets) - end
		targetList += fmt.Sprintf("\n\n  %s (showing %d-%d of %d, scroll for more)",
			sDim.Render(fmt.Sprintf("... %d more targets", remaining)), start+1, end, len(m.scanConfig.Targets))
	}

	// Invalid targets section (if any)
	invalidSection := ""
	if len(stats.Invalid) > 0 && len(stats.Invalid) <= 5 {
		invalidSection = "\n" + sWarn.Render("Skipped (invalid format):") + "\n"
		for _, inv := range stats.Invalid {
			invalidSection += fmt.Sprintf("  x  %s\n", inv)
		}
	} else if len(stats.Invalid) > 5 {
		invalidSection = fmt.Sprintf("\n%s (showing first 5 of %d)\n", sWarn.Render("Skipped (invalid format):"), len(stats.Invalid))
		for i, inv := range stats.Invalid {
			if i >= 5 {
				break
			}
			invalidSection += fmt.Sprintf("  x  %s\n", inv)
		}
	}

	panel := panelStyle(cBorderActive).Width(inner).Render(
		header + "\n" +
			sDim.Render(strings.Repeat("-", 42)) + "\n" +
			statsDisplay + "\n\n" +
			sDim.Render("Targets:") + "\n" +
			targetList +
			invalidSection,
	)

	help := sDim.Render("↑↓ scroll  ·  Enter confirm  ·  Esc back to edit")
	return panel + "\n\n" + help
}

func (m tuiModel) viewSelectPorts(w, h int) string {
	if m.tiStep == 1 {
		inner := w - 6
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CUSTOM PORTS ") + "\n\n" +
				sDim.Render("  e.g. 80,443,2053,2083,2087,2096,8443,8080-8090\n\n") +
				"  " + m.ti.View(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")
	}
	inner := w - 6
	visibleRows := h - 10
	if visibleRows < 3 {
		visibleRows = 3
	}

	start := 0
	if m.cursor >= visibleRows {
		start = m.cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(m.portPresets) {
		end = len(m.portPresets)
	}

	portColW := inner / 2
	if portColW < 18 {
		portColW = 18
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		preset := m.portPresets[i]
		parts := strings.SplitN(preset.label, " - ", 2)
		ports := strings.TrimSpace(parts[0])
		desc := ""
		if len(parts) > 1 {
			desc = strings.TrimSpace(parts[1])
		}

		line := fmt.Sprintf("%-*s  %s", portColW, ports, desc)
		if len([]rune(line)) > inner-4 {
			line = string([]rune(line)[:inner-5]) + "..."
		}

		if i == m.cursor {
			rows.WriteString(sSelected.Render(line) + "\n")
		} else {
			rows.WriteString(sNormal.Render(line) + "\n")
		}
	}

	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" SELECT PORTS ") + "\n\n" + rows.String(),
	)
	return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")
}

func (m tuiModel) viewSelectMethod(w, h int) string {
	labels := make([]string, len(m.methodOptions))
	copy(labels, m.methodOptions)

	// Add availability and fallback info
	if !scanner.ToolAvailable("masscan") {
		labels[1] += "  " + sWarn.Render("[unavailable->Direct]")
	}
	if !scanner.ToolAvailable("nmap") {
		labels[2] += "  " + sWarn.Render("[unavailable->Direct]")
	}

	help := "↑↓ navigate  ·  Enter select  ·  Esc back"
	if !scanner.ToolAvailable("masscan") || !scanner.ToolAvailable("nmap") {
		help += "  [unavailable tools fall back to Direct]"
	}

	return m.viewList(w, h, "SCAN METHOD", labels, help)
}

func (m tuiModel) viewToggleProbeFlags(w, h int) string {
	inner := w - 6
	title := sHeader.Render(" SETTINGS - PROBE HEURISTICS ")
	requireHTML := "OFF"
	acceptCert := "OFF"
	if m.app != nil && m.app.Scanner != nil {
		if m.app.Scanner.GetProbeRequireHTMLForDomainTokens() {
			requireHTML = "ON"
		}
		if m.app.Scanner.GetProbeAcceptOnCertMatch() {
			acceptCert = "ON"
		}
	}
	items := []string{
		fmt.Sprintf("Require HTML for domain tokens  [%s]", requireHTML),
		fmt.Sprintf("Accept on TLS cert match       [%s]", acceptCert),
	}
	var rows strings.Builder
	for i, item := range items {
		prefix := "[ ]"
		if i == m.cursor {
			prefix = "[>]"
		}
		line := fmt.Sprintf("%s %s", prefix, item)
		if i == m.cursor {
			rows.WriteString(sSelected.Render(line) + "\n")
		} else {
			rows.WriteString(sNormal.Render(line) + "\n")
		}
	}
	panel := panelStyle(cBorderActive).Width(inner).Render(
		title + "\n\n" + rows.String() + "\n" + sDim.Render("↑↓ navigate  ·  Enter/Space toggle  ·  Esc back"),
	)
	return panel
}

func (m tuiModel) viewSelectTransfer(w, h int) string {
	labels := make([]string, len(m.transferOptions))
	copy(labels, m.transferOptions)
	return m.viewList(w, h, "TRANSFER MODE", labels, "↑↓ navigate  ·  Enter select  ·  Esc back")
}

func (m tuiModel) viewSelectConcurrency(w, h int) string {
	return m.viewList(w, h, "CONCURRENCY", m.concurrencyOptions,
		"↑↓ navigate  ·  Enter select  ·  Esc back",
	)
}

func (m tuiModel) viewScanning(w, h int) string {
	inner := w - 4 // slightly wider scan panel

	opLabel := map[string]string{
		"scan_ips":       "IP Scan",
		"reload_pool":    "Pool Reload",
		"inspect_pool":   "Pool Inspect",
		"tls_probe":      "TLS Hostname Probe",
		"sni_scanner":    "SNI Scanner (TLS Hostname Probe)",
		"desync_scanner": "Desync Pair Miner (Native)",
	}[m.operationType]
	if opLabel == "" {
		opLabel = strings.ToUpper(m.scanKind) + " Proxy Scan"
	}

	// Progress bar
	progress := 0.0
	if m.scanTotal > 0 {
		progress = float64(m.scanProgress) / float64(m.scanTotal)
	}
	barW := inner - 12
	if barW < 10 {
		barW = 10
	}
	// Clamp progress so a total that undercounts actual work (e.g. the SNI
	// scanner reports CIDR-count, not expanded-IP-count) can never drive filled
	// past barW — strings.Repeat with a negative count panics and crashes the UI.
	if progress > 1.0 {
		progress = 1.0
	}
	if progress < 0 {
		progress = 0
	}
	filled := int(float64(barW) * progress)
	if filled > barW {
		filled = barW
	}
	if filled < 0 {
		filled = 0
	}
	// gradient: smooth interpolated hex gradient across filled width
	gradientStops := []string{"#00d1ff", "#7fff00", "#ffb400", "#ff4081", "#8a2be2"}
	// helper: interpolate between two hex colors
	mix := func(c1, c2 string, t float64) string {
		var r1, g1, b1 int
		var r2, g2, b2 int
		fmt.Sscanf(c1, "#%02x%02x%02x", &r1, &g1, &b1)
		fmt.Sscanf(c2, "#%02x%02x%02x", &r2, &g2, &b2)
		ri := int(float64(r1) + (float64(r2)-float64(r1))*t)
		gi := int(float64(g1) + (float64(g2)-float64(g1))*t)
		bi := int(float64(b1) + (float64(b2)-float64(b1))*t)
		return fmt.Sprintf("#%02x%02x%02x", ri, gi, bi)
	}

	left := ""
	if barW > 0 {
		for i := 0; i < filled; i++ {
			var t float64
			if barW > 1 {
				t = float64(i) / float64(barW-1)
			} else {
				t = 0
			}
			// map t across gradient stops
			segF := t * float64(len(gradientStops)-1)
			seg := int(math.Floor(segF))
			if seg < 0 {
				seg = 0
			}
			if seg >= len(gradientStops)-1 {
				seg = len(gradientStops) - 2
			}
			localT := segF - float64(seg)
			col := mix(gradientStops[seg], gradientStops[seg+1], localT)
			left += lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render("█")
		}
	}
	empty := sDim.Render(strings.Repeat("░", barW-filled))
	bar := left + empty + "  " + sAccent.Render(fmt.Sprintf("%3d%%", int(progress*100)))

	stats := fmt.Sprintf("  Probes: %s/%s   Found: %s   Unique IPs: %s",
		sInfo.Render(fmt.Sprintf("%d", m.scanProgress)),
		sInfo.Render(fmt.Sprintf("%d", m.scanTotal)),
		sSuccess.Render(fmt.Sprintf("%d", m.scanHits)),
		sInfo.Render(fmt.Sprintf("%d", m.scanTotalIPs)),
	)
	if len(m.scanConfig.Ports) > 0 && m.scanTotalIPs > 0 {
		stats += "   " + sDim.Render(fmt.Sprintf("ports %d", len(m.scanConfig.Ports)))
	}
	if !m.scanStartTime.IsZero() {
		stats += "   " + sDim.Render(fmt.Sprintf("elapsed %s", time.Since(m.scanStartTime).Round(time.Second)))
		if eta := scanETA(m.scanStartTime, m.scanProgress, m.scanTotal); eta != "" {
			stats += "   " + sDim.Render("eta "+eta)
		}
	}

	// Current IP being scanned
	currentIPLine := ""
	if m.scanCurrentIP != "" {
		currentIPLine = sDim.Render("  Scanning: ") + sPurple.Render(" "+m.scanCurrentIP)
	}

	// Ports being scanned (collapsed into ranges)
	portLabel := ""
	if len(m.scanConfig.Ports) > 0 {
		portLabel = compressPorts(m.scanConfig.Ports)
	} else {
		ports := m.app.Scanner.GetTargetPorts()
		if len(ports) > 0 {
			portLabel = compressPorts(ports)
		}
	}

	// Recent log lines
	logRows := h / 4
	if logRows < 5 {
		logRows = 5
	}
	if logRows > 10 {
		logRows = 10
	}
	logLines := m.recentLogs(logRows, inner-4)
	logBlock := sDim.Render(strings.Join(logLines, "\n"))

	// Live hits appear under the activity log so the progress area stays clean
	var liveRows strings.Builder
	// For SNI scanner we only show passed (OK) entries in the live view.
	if m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
		// collect last N passed entries
		n := len(m.scanResults)
		liveCount := h / 8
		if liveCount < 3 {
			liveCount = 3
		}
		if liveCount > 6 {
			liveCount = 6
		}
		collected := make([]string, 0, liveCount)
		for i := n - 1; i >= 0 && len(collected) < liveCount; i-- {
			r := m.scanResults[i]
			if strings.Contains(r, " OK ") {
				if len(r) > inner-6 {
					r = r[:inner-6]
				}
				collected = append(collected, r)
			}
		}
		for i := len(collected) - 1; i >= 0; i-- {
			liveRows.WriteString(sSuccess.Render("  > "+collected[i]) + "\n")
		}
	} else {
		n := len(m.scanResults)
		liveCount := h / 8
		if liveCount < 3 {
			liveCount = 3
		}
		if liveCount > 6 {
			liveCount = 6
		}
		start := n - liveCount
		if start < 0 {
			start = 0
		}
		for i := start; i < n; i++ {
			r := m.scanResults[i]
			// Other scans: strip extra proxy tags, just show IP:Port
			if !strings.Contains(r, ":") && len(portLabel) > 0 {
				r = fmt.Sprintf("%s:%s", r, portLabel)
			}
			endpoint := r
			if parts := strings.Fields(r); len(parts) > 1 && strings.Contains(parts[1], ":") {
				endpoint = parts[1]
			} else if len(parts) > 0 && strings.Contains(parts[0], ":") {
				endpoint = parts[0]
			}
			if len(endpoint) > inner-6 {
				endpoint = endpoint[:inner-6]
			}
			liveRows.WriteString(sSuccess.Render("  > "+endpoint) + "\n")
		}
	}

	headerBlock := m.spinner.View() + "  " + sHeader.Render(" "+opLabel+" ") + "\n\n"
	metaBlock := "  " + bar + "\n" + stats + "\n"
	if currentIPLine != "" {
		metaBlock += currentIPLine + "\n"
	}
	if portLabel != "" {
		metaBlock += sDim.Render("  Ports: ") + sPurple.Render(" "+portLabel) + "\n"
	}
	panel := panelStyle(cBorderActive).Width(inner).Render(
		headerBlock + metaBlock + "\n" +
			sAccent.Render("  Live results:\n") + liveRows.String() + "\n" +
			sHeader.Render(" ACTIVITY LOG ") + "\n" + logBlock,
	)
	return panel + "\n\n" + sDim.Render("p pause/resume  |  s save  |  c/q quit  |  Esc back")
}

func scanETA(start time.Time, current, total int) string {
	if start.IsZero() || current <= 0 || total <= 0 || current >= total {
		return ""
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		return ""
	}
	remaining := time.Duration(float64(elapsed) * float64(total-current) / float64(current))
	if remaining < 0 {
		return ""
	}
	return remaining.Round(time.Second).String()
}

func (m tuiModel) viewScanResults(w, h int) string {
	inner := w - 6
	visibleRows := h - 12
	if visibleRows < 3 {
		visibleRows = 3
	}

	opLabel := map[string]string{
		"scan_ips":       "IP Scan Results",
		"reload_pool":    "Pool Reload",
		"inspect_pool":   "Pool Inspect",
		"tls_probe":      "TLS Probe Results",
		"sni_scanner":    "SNI Scanner Results (TLS Hostname Probe)",
		"desync_scanner": "Desync Pair Miner Results",
	}[m.operationType]
	if opLabel == "" {
		opLabel = "Scan Results"
	}

	var body strings.Builder
	if m.scanErr != nil {
		body.WriteString(sError.Render("x "+m.scanErr.Error()) + "\n")
	} else {
		passedCount := len(m.scanResults)
		if m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
			passedCount = m.scanHits
		}
		body.WriteString(sSuccess.Render(fmt.Sprintf("  Usable results: %d\n", passedCount)))
		body.WriteString(sDim.Render("  failures stay in the log output only\n\n"))
		// Build display list: for SNI show only passed (OK) entries, failures remain only in logs/files
		displayResults := m.scanResults
		if m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
			filt := make([]string, 0, len(m.scanResults))
			for _, r := range m.scanResults {
				if strings.Contains(r, " OK ") {
					filt = append(filt, r)
				}
			}
			displayResults = filt
		}

		// Clamp cursor to displayResults
		if m.cursor >= len(displayResults) {
			m.cursor = len(displayResults) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}

		start := m.cursor - visibleRows + 1
		if start < 0 {
			start = 0
		}
		end := start + visibleRows
		if end > len(displayResults) {
			end = len(displayResults)
		}
		// Determine display ports: prefer explicit scanConfig, then scanner targets, then sensible defaults
		displayPorts := m.scanConfig.Ports
		if len(displayPorts) == 0 {
			displayPorts = m.app.Scanner.GetTargetPorts()
		}
		if len(displayPorts) == 0 {
			displayPorts = []int{443, 2053, 2083, 2087, 2096, 8443}
		}
		// render port label as comma-separated list
		var portStrs []string
		for _, p := range displayPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		portLabel := strings.Join(portStrs, ",")

		for i := start; i < end; i++ {
			r := displayResults[i]

			// For SNI, it might contain the full text "hostname ip OK/FAIL ... "
			// Wait, the dynamic append adds just IP. Let's fix that.
			if m.operationType != "sni_scanner" {
				if !strings.Contains(r, ":") && len(portLabel) > 0 {
					r = fmt.Sprintf("%s:%s", r, portLabel)
				}
			}

			// Color logic
			isCursor := (i == m.cursor)
			var rendered string

			if m.operationType == "sni_scanner" {
				// SNI scan: mark OK as green, FAIL as red. And show USABLE for passes.
				if strings.Contains(r, " OK ") {
					r = "USABLE " + r
					if len(r) > inner-6 {
						r = r[:inner-6]
					}
					if isCursor {
						rendered = sSelected.Render(r)
					} else {
						rendered = sSuccess.Render("  " + r)
					}
				} else if strings.Contains(r, " FAIL ") {
					if len(r) > inner-6 {
						r = r[:inner-6]
					}
					if isCursor {
						rendered = lipgloss.NewStyle().Bold(true).Foreground(cRed).Render("> " + r)
					} else {
						rendered = sError.Render("  " + r)
					}
				} else {
					// Fallback for live IP updates during SNI scan
					if len(r) > inner-6 {
						r = r[:inner-6]
					}
					if isCursor {
						rendered = sSelected.Render(r)
					} else {
						rendered = sDim.Render("  " + r)
					}
				}
			} else {
				// Other 3 scans: only IP:port in green, no USABLE tag
				// extract just the ip and port if it contains proxy formatted string
				endpoint := r
				if parts := strings.Fields(r); len(parts) > 1 && strings.Contains(parts[1], ":") {
					endpoint = parts[1] // handles "http 1.2.3.4:80 lat=..."
				} else if len(parts) > 0 && strings.Contains(parts[0], ":") {
					endpoint = parts[0]
				}

				if len(endpoint) > inner-6 {
					endpoint = endpoint[:inner-6]
				}
				if isCursor {
					rendered = sSelected.Render(endpoint)
				} else {
					rendered = sSuccess.Render("  " + endpoint)
				}
			}

			body.WriteString(rendered + "\n")
		}
		if len(m.scanResults) > visibleRows {
			body.WriteString(sDim.Render(fmt.Sprintf("\n  [%d/%d]", m.cursor+1, len(m.scanResults))))
		}
	}

	panel := panelStyle(cBorderAlt).Width(inner).Render(
		sHeader.Render(" "+strings.ToUpper(opLabel)+" ") + "\n\n" + body.String(),
	)
	return panel + "\n\n" + sDim.Render("up/down scroll  |  s save  |  Enter/q back to menu")
}

func (m tuiModel) viewManageDPISettings(w, h int) string {
	inner := w - 6
	state := m.dpiState
	items := make([]string, 0, 11)
	items = append(items, fmt.Sprintf("Target SNI/IP             [%s / %s]", state.DpiSNI, state.DpiIP))
	for _, opt := range dpiStrategyCatalog {
		mark := "[ ]"
		if state.strategyEnabled(opt.ID) {
			mark = "[x]"
		}
		items = append(items, fmt.Sprintf("%-9s %s", mark, strings.ToUpper(opt.ID)+" - "+opt.Description))
	}
	items = append(items, fmt.Sprintf("TCP Fragmentation        [%s]", boolLabel(state.DpiFragmentation, "ON", "OFF")))
	items = append(items, fmt.Sprintf("DPI Logs Visibility      [%s]", boolLabel(state.AlwaysShowDpiLogs, "ON", "OFF (Auto-hide)")))
	items = append(items, "Save and return")

	var rows strings.Builder
	for i, item := range items {
		if i == m.cursor {
			rows.WriteString(sSelected.Render(item) + "\n")
		} else {
			rows.WriteString(sNormal.Render(item) + "\n")
		}
	}

	help := "↑↓ navigate  ·  Enter toggle/select  ·  t target  ·  s save  ·  Esc back"
	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" DESYNC SETTINGS ") + "\n\n" + rows.String(),
	)
	return panel + "\n\n" + sDim.Render(help)
}

func (m tuiModel) viewSimpleInput(w, h int, title, placeholder string) string {
	inner := w - 6
	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" "+strings.ToUpper(title)+" ") + "\n\n" +
			sDim.Render("  "+placeholder+"\n\n") +
			"  " + m.ti.View(),
	)
	return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")
}

func (m tuiModel) viewEditDPITarget(w, h int) string {
	inner := w - 6
	state := m.dpiState
	var prompt string
	if m.tiStep == 1 {
		prompt = fmt.Sprintf("Current SNI: %s\n\nEnter DPI SNI", state.DpiSNI)
	} else {
		prompt = fmt.Sprintf("Current SNI: %s\nCurrent IP: %s\n\nEnter clean IP", state.DpiSNI, state.DpiIP)
	}
	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" EDIT DPI TARGET ") + "\n\n" +
			sInfo.Render("  "+prompt+"\n\n") +
			"  " + m.ti.View(),
	)
	return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")
}

func (m tuiModel) viewManageTLSProbe(w, h int) string {
	inner := w - 6
	custom := tlsprobe.LoadCustom(m.app.DataDir)
	merged := tlsprobe.GetDomains(m.app.DataDir)
	var rows strings.Builder
	rows.WriteString(fmt.Sprintf("Custom domains: %d\nAll probe domains: %d\n\n", len(custom), len(merged)))
	if len(custom) == 0 {
		rows.WriteString("  (no custom probe domains yet)\n\n")
	} else {
		limit := len(custom)
		if limit > 8 {
			limit = 8
		}
		for i := 0; i < limit; i++ {
			rows.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, custom[i]))
		}
		if len(custom) > limit {
			rows.WriteString(fmt.Sprintf("  ... and %d more\n\n", len(custom)-limit))
		} else {
			rows.WriteString("\n")
		}
	}
	panel := panelStyle(cBorderActive).Width(inner).Render(
		sHeader.Render(" MANAGE SNI PROBE DOMAINS ") + "\n\n" +
			sInfo.Render(rows.String()) +
			"  " + m.ti.View(),
	)
	return panel + "\n\n" + sDim.Render("Paste domains and press Enter to save  |  Esc back")
}

// ------------------------------------------------------------
//  Screen handlers
// ------------------------------------------------------------

func (m tuiModel) handleMenuScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	half := (len(m.menu) + 1) / 2
	leftLen := half
	rightLen := len(m.menu) - half
	if m.menuCol == 0 && m.menuRow >= leftLen {
		m.menuRow = leftLen - 1
	}
	if m.menuCol == 1 && m.menuRow >= rightLen {
		m.menuRow = rightLen - 1
	}
	if m.menuRow < 0 {
		m.menuRow = 0
	}
	if m.menuCol < 0 {
		m.menuCol = 0
	}
	if m.menuCol > 1 {
		m.menuCol = 1
	}
	if m.menuCol == 0 {
		m.cursor = m.menuRow
	} else {
		m.cursor = half + m.menuRow
	}
	switch k.String() {
	case "up", "k":
		if m.menuRow > 0 {
			m.menuRow--
		}
	case "down", "j":
		if m.menuCol == 0 {
			if m.menuRow+1 < leftLen {
				m.menuRow++
			}
		} else if m.menuRow+1 < rightLen {
			m.menuRow++
		}
	case "left", "h":
		if m.menuCol == 1 {
			m.menuCol = 0
			if m.menuRow >= leftLen {
				m.menuRow = leftLen - 1
			}
		}
	case "right", "l":
		if m.menuCol == 0 && m.menuRow < rightLen {
			m.menuCol = 1
			if m.menuRow >= rightLen {
				m.menuRow = rightLen - 1
			}
		}
	case "q", "0":
		return m, tea.Quit
	case "enter":
		if m.menuCol == 0 {
			m.cursor = m.menuRow
		} else {
			m.cursor = half + m.menuRow
		}
		return m.activateMenuItem()
	}
	if m.menuCol == 0 {
		m.cursor = m.menuRow
	} else {
		m.cursor = half + m.menuRow
	}
	return m, nil
}

func (m tuiModel) handleToggleProbeFlagsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "1", "enter", " ":
		if m.app != nil && m.app.Scanner != nil {
			if m.cursor == 0 {
				cur := m.app.Scanner.GetProbeRequireHTMLForDomainTokens()
				newVal := !cur
				m.app.Scanner.SetProbeRequireHTMLForDomainTokens(newVal)
				m.addLog(fmt.Sprintf("Probe RequireHTML toggled -> %v", newVal))
				m.app.Cfg.ProbeRequireHTMLForDomainTokens = newVal
				_ = config.SaveToFile(m.app.Cfg, storage.GetPaths().ConfigFile)
			} else {
				cur := m.app.Scanner.GetProbeAcceptOnCertMatch()
				newVal := !cur
				m.app.Scanner.SetProbeAcceptOnCertMatch(newVal)
				m.addLog(fmt.Sprintf("Probe AcceptOnCertMatch toggled -> %v", newVal))
				m.app.Cfg.ProbeAcceptOnCertMatch = newVal
				_ = config.SaveToFile(m.app.Cfg, storage.GetPaths().ConfigFile)
			}
		}
	case "2":
		if m.app != nil && m.app.Scanner != nil {
			cur := m.app.Scanner.GetProbeAcceptOnCertMatch()
			newVal := !cur
			m.app.Scanner.SetProbeAcceptOnCertMatch(newVal)
			m.addLog(fmt.Sprintf("Probe AcceptOnCertMatch toggled -> %v", newVal))
			m.app.Cfg.ProbeAcceptOnCertMatch = newVal
			_ = config.SaveToFile(m.app.Cfg, storage.GetPaths().ConfigFile)
		}
	case "esc", "b":
		m.goBack()
	}
	return m, nil
}

func (m tuiModel) activateMenuItem() (tuiModel, tea.Cmd) {
	item := m.menu[m.cursor]
	switch item.action {
	case "scan_ips":
		m.gotoScanMode("scan_ips", "ipscan")
	case "scan":
		m.gotoScanMode("scan", "http")
	case "scan_socks5":
		m.gotoScanMode("scan", "socks5")
	case "reload_pool":
		m.pushScreen(screenSelectASN)
		m.operationType = "reload_pool"
		m.resetASNScreen("Search ASN for pool reload")
	case "manage_pool":
		return m, m.cmdManagePool()
	case "inspect_ip":
		m.pushScreen(screenSelectASN)
		m.operationType = "inspect_pool"
		m.resetASNScreen("Search ASN to inspect")
	case "export_asn":
		m.pushScreen(screenSelectASN)
		m.operationType = "export_asn"
		m.scanConfig.ASNs = nil
		m.resetASNScreen("Search ASN to export")
	case "edit_dpi_target":
		m.pushScreen(screenEditDPITarget)
		m.tiStep = 1
		m.setupInput("Enter DPI SNI")
	case "autotune":
		m.setToast(sInfo.Render("Tip: use direct for <30 targets, masscan for large scans"), 5*time.Second)
	case "desync_scanner":
		m.addLog("Desync Pair Miner opened (native flow)")
		m.setToast(sInfo.Render("Native mode: scans SNI/IP pairs and writes desync_pairs.json"), 5*time.Second)
		m.gotoScanMode("desync_scanner", "sni_scanner")
		return m, nil
	case "sni_scanner":
		m.addLog("SNI Scanner (TLS Hostname Probe) selected")
		m.gotoScanMode("sni_scanner", "sni_scanner")
		// Ask which SNI hostnames to probe before choosing IP targets.
		m.screen = screenSNISource
		m.cursor = 0
		m.tiStep = 0
	case "config_maker":
		m.pushScreen(screenConfigMaker)
		m.initConfigMaker()
		m.addLog("Opened Config Maker")
		m.cursor = 0
	case "manage_tls_probe":
		m.pushScreen(screenManageTLSProbe)
		m.tiStep = 1
		m.setupInput("Add domain to TLS probe list (one per line)")
	case "toggle_probe_flags":
		m.pushScreen(screenToggleProbeFlags)
		m.cursor = 0
		m.tiStep = 0
	case "configure_desync":
		m.pushScreen(screenManageDPISettings)
		m.cursor = 0
		m.dpiState = loadDPIState(m.app.DataDir)
		m.addLog("Opened Desync Settings")
	case "clear_cache":
		m.app.Router.ClearAllRoutes()
		m.app.Scanner.ClearCache()
		m.addLog("Cache cleared")
		m.setToast(sSuccess.Render("OK Cache cleared"), 3*time.Second)
	case "exit":
		return m, tea.Quit
	}
	return m, nil
}

func (m tuiModel) handleScanModeScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 2 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			m.pushScreen(screenSelectASN)
			m.scanConfig.Mode = "asn"
			m.resetASNScreen("Search ASN")
		case 1:
			m.scanConfig.Mode = "paste"
			m.pushScreen(screenTypeTargets)
			m.setupInput("Paste targets (IPs/CIDRs, space or newline)")
		case 2:
			m.scanConfig.Mode = "type"
			m.pushScreen(screenTypeTargets)
			m.setupInput("Type targets (IPs/CIDRs, space or newline)")
			// For TLS probe, also show 3 mode options (ASN, paste, type)
			// but we don't add case 3 here; instead we detect operationType elsewhere
		}
	}
	return m, nil
}

// handleSNISourceScreen lets the user choose the SNI hostnames probed by the
// SNI scanner: the managed default list, or their own domains entered inline.
func (m tuiModel) handleSNISourceScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.tiStep == 1 {
		if m.pasteClipboardIntoInput(msg, false) {
			return m, nil
		}
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			domains := parseSNIDomains(m.ti.Value())
			if len(domains) == 0 {
				m.setToast(sError.Render("x Enter at least one valid domain"), 3*time.Second)
				return m, nil
			}
			m.scanConfig.SNIDomains = domains
			m.addLog(fmt.Sprintf("Using %d custom SNI domain(s)", len(domains)))
			m.ti.Blur()
			m.tiStep = 0
			m.screen = screenSNIMode
			m.cursor = 0
			return m, nil
		}
		m.ti, _ = m.ti.Update(msg)
		return m, nil
	}

	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "enter":
		if m.cursor == 1 {
			m.tiStep = 1
			m.setupInput("Domains e.g. example.com, cdn.example.net")
			return m, nil
		}
		m.scanConfig.SNIDomains = nil
		m.addLog("Using default SNI probe domains")
		m.screen = screenSNIMode
		m.cursor = 0
	}
	return m, nil
}

// handleSNIModeScreen lets the user choose strict SNI matching (for
// domain-fronting / SNI-spoofing discovery) versus lenient reachability.
func (m tuiModel) handleSNIModeScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "enter":
		m.scanConfig.SNIStrict = m.cursor == 0
		if m.scanConfig.SNIStrict {
			m.addLog("SNI mode: strict (SNI must be accepted; cert match reported)")
		} else {
			m.addLog("SNI mode: lenient (any TLS handshake counts)")
		}
		m.screen = screenScanMode
		m.cursor = 0
	}
	return m, nil
}

func (m tuiModel) viewSNIMode(w, h int) string {
	items := []string{
		"Strict - SNI must be accepted (domain fronting / spoof)",
		"Lenient - any TLS handshake counts (reachability)",
	}
	return m.viewList(w, h, "SNI MATCH MODE", items, "↑↓ navigate  ·  Enter select  ·  Esc back")
}

// parseSNIDomains splits a raw user string into normalized, deduped domains.
func parseSNIDomains(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}) {
		d := strings.ToLower(strings.TrimSpace(field))
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimSuffix(d, "/")
		if d == "" || !strings.Contains(d, ".") {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func (m tuiModel) handleSelectASNScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if ok {
		switch k.String() {
		case ";":
			m.typingEnabled = !m.typingEnabled
			if m.typingEnabled {
				m.ti.Focus()
			} else {
				m.ti.Blur()
			}
			return m, nil
		}
	}

	// Only route keys into the search box while typing is enabled.
	if m.typingEnabled {
		if m.pasteClipboardIntoInput(msg, false) {
			return m, nil
		}
		m.ti, _ = m.ti.Update(msg)
	} else {
		// Keep the input untouched while selection mode is active.
		m.ti.Blur()
	}
	query := strings.ToLower(strings.TrimSpace(m.ti.Value()))
	if query == "" {
		m.asnFiltered = m.asnList
	} else {
		m.asnFiltered = nil
		for _, e := range m.asnList {
			if strings.Contains(strings.ToLower(e.ASName), query) ||
				strings.Contains(strings.ToLower(e.ASN), query) {
				m.asnFiltered = append(m.asnFiltered, e)
			}
		}
	}
	// clamp cursor
	if m.cursor >= len(m.asnFiltered) {
		m.cursor = len(m.asnFiltered) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}

	switch k.String() {
	case "up", "ctrl+p":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "ctrl+n":
		if m.cursor < len(m.asnFiltered)-1 {
			m.cursor++
		}
	case "tab":
		if m.cursor < len(m.asnFiltered) {
			m.selectedItems[m.cursor] = !m.selectedItems[m.cursor]
		}
	case " ":
		if !m.typingEnabled {
			if m.cursor < len(m.asnFiltered) {
				m.selectedItems[m.cursor] = !m.selectedItems[m.cursor]
			}
		}
	case "enter":
		if strings.EqualFold(strings.TrimSpace(m.ti.Value()), "/all") {
			m.selectAllASNs()
			return m, nil
		}
		if len(m.selectedItems) == 0 {
			m.setToast(sError.Render("x Select at least one ASN"), 3*time.Second)
			return m, nil
		}
		for idx := range m.selectedItems {
			if idx < len(m.asnFiltered) {
				// Add all networks for this ASN
				m.scanConfig.ASNs = append(m.scanConfig.ASNs, m.asnFiltered[idx].Networks...)
			}
		}
		if m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
			expandedIPs := len(tlsprobe.ExpandTargets(m.scanConfig.ASNs))
			m.addLog(fmt.Sprintf("Selected %d ASN networks (%d expanded IPs for SNI scan)", len(m.scanConfig.ASNs), expandedIPs))
		} else {
			m.addLog(fmt.Sprintf("Selected %d ASN networks", len(m.scanConfig.ASNs)))
		}

		if m.operationType == "export_asn" {
			path, count, err := exportASNTargetsToTXT(m.app.DataDir, m.scanConfig.ASNs, "")
			if err != nil {
				m.addLog(fmt.Sprintf("ASN export failed: %v", err))
				m.setToast(sError.Render("x "+err.Error()), 5*time.Second)
			} else {
				m.addLog(fmt.Sprintf("Exported %d IPs to %s", count, path))
				m.setToast(sSuccess.Render(fmt.Sprintf("OK Exported %d IPs", count)), 4*time.Second)
			}
			m.goBack()
			return m, nil
		}

		if m.operationType == "reload_pool" || m.operationType == "inspect_pool" {
			m.startOperation()
			return m, m.cmdPoolOperation(m.operationType, m.scanConfig.ASNs)
		}
		m.pushScreen(screenSelectPorts)
		m.cursor = 0
	}
	return m, nil
}

func (m *tuiModel) selectAllASNs() {
	if len(m.asnList) == 0 {
		return
	}
	m.selectedItems = make(map[int]bool, len(m.asnList))
	for i := range m.asnList {
		m.selectedItems[i] = true
	}
	m.asnFiltered = m.asnList
	m.cursor = 0
	m.ti.SetValue("")
	if m.operationType == "export_asn" {
		m.setToast(sSuccess.Render(fmt.Sprintf("OK Selected all %d ASNs", len(m.asnList))), 3*time.Second)
	}
}

func (m tuiModel) handleTypeTargetsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if m.pasteClipboardIntoInput(msg, true) {
		m.setToast(sInfo.Render("Pasted — press Enter to review"), 2*time.Second)
		return m, nil
	}
	// Bracketed paste: the terminal delivers the whole paste (with newlines) in
	// one KeyMsg. Capture it directly so we never depend on an OS clipboard tool.
	if ok && k.Paste {
		m.pasteBuffer += string(k.Runes)
		// Show a single-line preview in the input so the user sees it registered.
		flat := strings.Join(strings.Fields(strings.ReplaceAll(m.pasteBuffer, "\n", " ")), " ")
		m.ti.SetValue(flat)
		m.setToast(sInfo.Render("Pasted — press Enter to review"), 2*time.Second)
		return m, nil
	}
	if ok && k.String() == "enter" {
		raw := m.ti.Value()
		havePaste := strings.TrimSpace(m.pasteBuffer) != ""
		if havePaste {
			// Bracketed paste already captured the full multi-line content, so
			// submit it directly — no rapid-Enter filtering, confirm step, or
			// OS-clipboard dependency needed.
			raw = m.pasteBuffer
		} else if m.scanConfig.Mode == "paste" {
			// Fallback path for terminals without bracketed paste (newlines arrive
			// as Enter keystrokes). Filter rapid-fire Enters from pasted newlines.
			now := time.Now()
			if !m.lastEnterTime.IsZero() && now.Sub(m.lastEnterTime) < 50*time.Millisecond {
				m.lastEnterTime = now
				m.ti, _ = m.ti.Update(msg)
				return m, nil
			}
			m.lastEnterTime = now

			// Require a confirmation Enter to avoid instant submission when pasting.
			if !m.pasteConfirm {
				m.pasteConfirm = true
				m.pasteConfirmAt = time.Now()
				m.setToast(sInfo.Render("Press Enter again to proceed with review"), 2*time.Second)
				return m, nil
			}
			if time.Since(m.pasteConfirmAt) > 10*time.Second {
				m.pasteConfirmAt = time.Now()
				m.setToast(sInfo.Render("Press Enter again to proceed with review"), 2*time.Second)
				return m, nil
			}
			m.pasteConfirm = false
			// Note: the OS clipboard is intentionally NOT read here. Doing so
			// injected whatever was already on the clipboard (e.g. IPs copied
			// earlier) even when the user pasted nothing. Real pastes are captured
			// via bracketed paste (m.pasteBuffer) above.

			// Last resort: pull from the OS clipboard (works on Windows/macOS; on
			// Linux requires xclip/xsel, which is why bracketed paste is preferred).
			if clipText := readClipboardText(); clipText != "" {
				raw = clipText
			}
		}

		raw = strings.TrimSpace(raw)
		m.pasteBuffer = ""
		m.pasteConfirm = false
		if raw == "" {
			m.goBack()
			return m, nil
		}

		// Parse targets from raw input using robust parser
		stats := scanner.ParseTargetsFromPaste(raw)
		m.parsedTargetStats = &stats
		m.parsedTargetsScroll = 0
		m.cursor = 0

		// Check if any valid targets were found
		if len(stats.Valid) == 0 {
			m.addLog("ERROR: No valid targets found in input")
			m.setToast(sError.Render("No valid IPs/CIDRs found"), 3*time.Second)
			return m, nil
		}

		// Set parsed targets
		m.scanConfig.Targets = stats.Valid
		m.scanConfig.ASNs = nil

		// Navigate to review screen
		m.pushScreen(screenReviewTargets)
		m.ti.Blur()
		return m, nil
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

func (m tuiModel) handleReviewTargetsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch k.String() {
	case "enter":
		// Proceed to port selection
		m.addLog(fmt.Sprintf("Confirmed %d targets (%d invalid skipped)", len(m.scanConfig.Targets), len(m.parsedTargetStats.Invalid)))
		m.pushScreen(screenSelectPorts)
		m.cursor = 0
		return m, nil
	case "esc":
		// Go back to input
		m.goBack()
		return m, nil
	case "up", "k":
		if m.parsedTargetsScroll > 0 {
			m.parsedTargetsScroll--
		}
		return m, nil
	case "down", "j":
		maxScroll := len(m.scanConfig.Targets) - 1
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.parsedTargetsScroll < maxScroll {
			m.parsedTargetsScroll++
		}
		return m, nil
	}
	return m, nil
}

func (m tuiModel) handleSelectPortsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.tiStep == 1 {
		if m.pasteClipboardIntoInput(msg, false) {
			return m, nil
		}
		k, ok := msg.(tea.KeyMsg)
		if ok && k.String() == "enter" {
			m.scanConfig.PortsString = strings.TrimSpace(m.ti.Value())
			m.scanConfig.Ports = parsePorts(m.scanConfig.PortsString)
			m.ti.Blur()
			m.tiStep = 0
			if m.operationType == "scan_ips" {
				m.pushScreen(screenSelectConcurrency)
			} else {
				m.pushScreen(screenSelectMethod)
			}
			m.cursor = 0
			return m, nil
		}
		m.ti, _ = m.ti.Update(msg)
		return m, nil
	}

	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.portPresets)-1 {
			m.cursor++
		}
	case "enter":
		if m.cursor < len(m.portPresets) {
			preset := m.portPresets[m.cursor]
			if preset.ports == "" {
				m.tiStep = 1
				m.setupInput("Ports e.g. 80,443,2053,2083,2087,2096,8443,8080-8090")
				return m, nil
			}
			m.scanConfig.PortsString = preset.ports
			m.scanConfig.Ports = parsePorts(m.scanConfig.PortsString)
		}
		if m.operationType == "scan_ips" || m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
			m.pushScreen(screenSelectConcurrency)
			m.cursor = 1
		} else {
			m.pushScreen(screenSelectMethod)
			m.cursor = 0
		}
	}
	return m, nil
}

func (m tuiModel) handleSelectMethodScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.methodOptions)-1 {
			m.cursor++
		}
	case "enter":
		methods := []string{"direct", "masscan", "nmap"}
		m.scanConfig.Method = methods[m.cursor]
		m.addLog(fmt.Sprintf("OK Scan method: %s", strings.ToUpper(m.scanConfig.Method)))
		if m.scanKind == "http" || m.scanKind == "socks5" {
			m.pushScreen(screenSelectTransfer)
			m.cursor = 0
			return m, nil
		}

		m.pushScreen(screenSelectConcurrency)
		m.cursor = 1
	}
	return m, nil
}

func (m tuiModel) handleSelectTransferScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.transferOptions)-1 {
			m.cursor++
		}
	case "enter":
		models := []string{"old", "brrr"}
		m.scanConfig.TransferModel = models[m.cursor]
		m.addLog(fmt.Sprintf("OK Transfer mode: %s", strings.ToUpper(m.scanConfig.TransferModel)))
		m.pushScreen(screenSelectConcurrency)
		m.cursor = 1
	}
	return m, nil
}

func (m tuiModel) handleSelectConcurrencyScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	// Index 0 is the low-bandwidth profile (50 workers, long timeouts); the
	// remaining entries mirror the standard concurrency presets.
	vals := []int{50, 50, 250, 500, 1000, 2000, 5000}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.concurrencyOptions)-1 {
			m.cursor++
		}
	case "enter":
		sel := vals[m.cursor]
		if sel > maxAllowedConcurrency {
			m.addLog(fmt.Sprintf("Requested concurrency %d exceeds max %d - capping to %d", sel, maxAllowedConcurrency, maxAllowedConcurrency))
			sel = maxAllowedConcurrency
		}
		m.scanConfig.LowBandwidth = m.cursor == 0
		m.scanConfig.Concurrency = sel
		if m.scanConfig.LowBandwidth {
			m.scanConfig.AdaptiveDomainConcurrency = 1
			m.addLog(fmt.Sprintf("Low-bandwidth mode: concurrency=%d with extended verification timeouts", sel))
		} else {
			m.scanConfig.AdaptiveDomainConcurrency = 0
			m.addLog(fmt.Sprintf("Concurrency set to %d", m.scanConfig.Concurrency))
		}
		m.startOperation()

		targets := m.scanConfig.ASNs
		if len(targets) == 0 {
			targets = m.scanConfig.Targets
		}
		ports := m.scanConfig.Ports
		if len(ports) == 0 {
			ports = parsePorts(m.scanConfig.PortsString)
		}

		if m.operationType == "scan_ips" {
			endpointCount := len(targets) * len(ports)
			timeout := scanTimeoutBudget(endpointCount, m.scanConfig.LowBandwidth)
			m.startScanLogFile("ipscan", targets, ports, m.scanConfig.Concurrency, timeout)
			m.app.Scanner.SetTargetPorts(ports)
			m.scanMsgCh = make(chan tea.Msg, 65536)
			m.addLog(fmt.Sprintf("Starting IP scan: targets=%d ports=%d concurrency=%d method=%s", len(targets), len(ports), m.scanConfig.Concurrency, strings.ToUpper(strings.TrimSpace(m.scanConfig.Method))))
			m.addLog(fmt.Sprintf("Scan log file: %s", m.scanLogPath))
			return m, m.cmdPoolOperation("scan_ips", targets)
		}
		if m.operationType == "sni_scanner" {
			endpointCount := len(targets) * len(ports)
			timeout := scanTimeoutBudget(endpointCount, m.scanConfig.LowBandwidth)
			m.startScanLogFile("sni_scanner", targets, ports, m.scanConfig.Concurrency, timeout)
			m.app.Scanner.SetTargetPorts(ports)
			m.scanMsgCh = make(chan tea.Msg, 65536)
			m.addLog(fmt.Sprintf("Starting TLS Hostname Probe: targets=%d ports=%d concurrency=%d", len(targets), len(ports), m.scanConfig.Concurrency))
			m.addLog(fmt.Sprintf("Scan log file: %s", m.scanLogPath))
			return m, m.cmdPoolOperation("sni_scanner", targets)
		}
		if m.operationType == "desync_scanner" {
			endpointCount := len(targets) * len(ports)
			timeout := scanTimeoutBudget(endpointCount, m.scanConfig.LowBandwidth)
			m.startScanLogFile("desync_scanner", targets, ports, m.scanConfig.Concurrency, timeout)
			m.app.Scanner.SetTargetPorts(ports)
			m.scanMsgCh = make(chan tea.Msg, 65536)
			m.addLog(fmt.Sprintf("Starting Desync Pair Miner: targets=%d ports=%d concurrency=%d", len(targets), len(ports), m.scanConfig.Concurrency))
			m.addLog(fmt.Sprintf("Scan log file: %s", m.scanLogPath))
			return m, m.cmdPoolOperation("desync_scanner", targets)
		}
		timeout := proxyScanTimeout(m.scanConfig.Concurrency, m.scanConfig.LowBandwidth)
		m.startScanLogFile(m.scanKind, targets, ports, m.scanConfig.Concurrency, timeout)
		m.app.Scanner.SetTargetPorts(ports)
		m.scanMsgCh = make(chan tea.Msg, 65536)
		m.addLog(fmt.Sprintf("Starting proxy scan: targets=%d ports=%d concurrency=%d", len(targets), len(ports), m.scanConfig.Concurrency))
		m.addLog(fmt.Sprintf("Scan log file: %s", m.scanLogPath))
		return m, m.cmdProxyScan(targets, m.scanConfig, m.scanKind)
	}
	return m, nil
}

func (m tuiModel) handleScanningScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "c":
			if m.scanCancel != nil {
				m.scanCancel()
				m.addLog("Scan cancelled")
			}
			m.goBack()
		case "q":
			if m.scanCancel != nil {
				m.scanCancel()
				m.addLog("Scan cancelled")
			}
			m.goBack()
		case "p":
			// toggle pause
			if m.scanPaused {
				m.scanPaused = false
				if m.app.Scanner != nil {
					m.app.Scanner.Resume()
				}
				m.addLog("Scan resumed")
				m.setToast(sSuccess.Render("Resumed"), 2*time.Second)
			} else {
				m.scanPaused = true
				if m.app.Scanner != nil {
					m.app.Scanner.Pause()
				}
				m.addLog("Scan paused")
				m.setToast(sWarn.Render("Paused"), 2*time.Second)
			}
		case "s":
			kind := m.operationType
			if kind == "" {
				kind = m.scanKind
			}
			if path, err := saveScanOutputResults(m.app.DataDir, kind, m.scanResults, m.operationType); err != nil {
				m.addLog(fmt.Sprintf("Failed to save scan output: %v", err))
				m.setToast(sError.Render("x Save failed"), 3*time.Second)
			} else {
				m.addLog(fmt.Sprintf("Saved scan output to %s", path))
				m.setToast(sSuccess.Render("OK Saved scan output"), 3*time.Second)
			}
		}
	}
	return m, nil
}

func (m tuiModel) handleManageDPISettingsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(dpiStrategyCatalog)+3 {
				m.cursor++
			}
		case "t":
			m.pushScreen(screenEditDPITarget)
			m.tiStep = 1
			m.setupInput("Enter DPI SNI")
			return m, nil
		case "s":
			if err := saveDPIState(m.app.DataDir, m.dpiState); err != nil {
				m.setToast(sError.Render("x Failed to save DPI settings"), 3*time.Second)
			} else {
				m.addLog("Saved desync settings")
				m.setToast(sSuccess.Render("OK DPI settings saved"), 3*time.Second)
			}
			m.goBack()
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.pushScreen(screenEditDPITarget)
				m.tiStep = 1
				m.setupInput("Enter DPI SNI")
			case 1, 2, 3, 4, 5, 6, 7:
				idx := m.cursor - 1
				if idx >= 0 && idx < len(dpiStrategyCatalog) {
					m.dpiState.toggleStrategy(dpiStrategyCatalog[idx].ID)
					_ = saveDPIState(m.app.DataDir, m.dpiState)
					m.addLog(fmt.Sprintf("Toggled DPI strategy: %s", dpiStrategyCatalog[idx].ID))
				}
			case 8:
				m.dpiState.DpiFragmentation = !m.dpiState.DpiFragmentation
				_ = saveDPIState(m.app.DataDir, m.dpiState)
				m.addLog(fmt.Sprintf("DPI fragmentation -> %v", m.dpiState.DpiFragmentation))
			case 9:
				m.dpiState.AlwaysShowDpiLogs = !m.dpiState.AlwaysShowDpiLogs
				_ = saveDPIState(m.app.DataDir, m.dpiState)
				m.addLog(fmt.Sprintf("DPI logs visibility -> %v", m.dpiState.AlwaysShowDpiLogs))
			case 10:
				if err := saveDPIState(m.app.DataDir, m.dpiState); err != nil {
					m.setToast(sError.Render("x Failed to save DPI settings"), 3*time.Second)
				} else {
					m.addLog("Saved desync settings")
					m.setToast(sSuccess.Render("OK DPI settings saved"), 3*time.Second)
				}
				m.goBack()
				return m, nil
			}
		case "q", "0", "esc":
			m.goBack()
			return m, nil
		}
	}
	return m, nil
}

func (m tuiModel) handleEditDPITargetScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.pasteClipboardIntoInput(msg, false) {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		raw := strings.TrimSpace(m.ti.Value())
		if raw == "" {
			m.goBack()
			return m, nil
		}
		if m.tiStep == 1 {
			m.dpiState.DpiSNI = raw
			m.tiStep = 2
			m.setupInput("Enter clean IP")
			return m, nil
		}
		m.dpiState.DpiIP = raw
		_ = saveDPIState(m.app.DataDir, m.dpiState)
		m.addLog(fmt.Sprintf("Updated DPI target: sni=%s ip=%s", m.dpiState.DpiSNI, m.dpiState.DpiIP))
		m.setToast(sSuccess.Render("OK DPI target saved"), 3*time.Second)
		m.ti.Blur()
		m.goBack()
		return m, nil
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

func (m tuiModel) handleManageTLSProbeScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.pasteClipboardIntoInput(msg, false) {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		raw := strings.TrimSpace(m.ti.Value())
		if raw == "" {
			m.goBack()
			return m, nil
		}
		// allow multiple domains pasted separated by newline or space
		parts := strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' })
		if len(parts) == 0 {
			m.goBack()
			return m, nil
		}
		// load existing custom domains and merge
		existing := tlsprobe.LoadCustom(m.app.DataDir)
		merged := append([]string{}, existing...)
		merged = append(merged, parts...)
		_ = tlsprobe.SaveCustom(m.app.DataDir, merged)
		m.addLog(fmt.Sprintf("Saved %d TLS probe domains", len(tlsprobe.GetDomains(m.app.DataDir))))
		m.ti.Blur()
		m.goBack()
		return m, nil
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

func (m tuiModel) handleInspectIPScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.pasteClipboardIntoInput(msg, false) {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		raw := strings.TrimSpace(m.ti.Value())
		if raw == "" {
			m.goBack()
			return m, nil
		}
		m.startOperation()
		return m, m.cmdInspectIP(raw)
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

func (m tuiModel) handleScanResultsScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.scanResults)-1 {
				m.cursor++
			}
		case "s":
			kind := m.operationType
			if kind == "" {
				kind = m.scanKind
			}
			if path, err := saveScanOutputResults(m.app.DataDir, kind, m.scanResults, m.operationType); err != nil {
				m.addLog(fmt.Sprintf("Failed to save scan output: %v", err))
				m.setToast(sError.Render("x Save failed"), 3*time.Second)
			} else {
				m.addLog(fmt.Sprintf("Saved scan output to %s", path))
				m.setToast(sSuccess.Render("OK Saved scan output"), 3*time.Second)
			}
		case "enter", "q", "backspace":
			m.screen = screenMenu
			m.scanResults = nil
			m.cursor = 0
		}
	}
	return m, nil
}

// ------------------------------------------------------------
//  Completion handlers
// ------------------------------------------------------------

func (m tuiModel) handleScanComplete(msg scanCompleteMsg) (tuiModel, tea.Cmd) {
	m.scanResults = msg.proxies
	m.scanErr = msg.err
	if m.scanTotal <= 0 {
		m.scanTotal = 1
	}
	m.scanProgress = m.scanTotal
	m.scanMsgCh = nil
	m.scanCtx = nil
	m.scanCancel = nil
	if msg.err != nil {
		m.writeScanLogLine(fmt.Sprintf("[COMPLETE] scan failed: %v", msg.err))
	} else {
		m.writeScanLogLine(fmt.Sprintf("[COMPLETE] scan done: %d proxies in %s", len(msg.proxies), msg.duration))
		if path, err := saveScanOutputResults(m.app.DataDir, m.scanKind, m.scanResults, m.operationType); err != nil {
			m.addLog(fmt.Sprintf("Failed to save scan output: %v", err))
		} else {
			m.addLog(fmt.Sprintf("Saved scan output to %s", path))
		}
	}
	// SNI/desync write incremental passed/failed/CSV files from the live result
	// loop because they need per-probe detail. Other operations append here.
	if m.operationType != "sni_scanner" && m.operationType != "desync_scanner" {
		m.appendNewScanResultsToFile()
	}
	if msg.err != nil {
		m.addLog(fmt.Sprintf("Scan failed: %v", msg.err))
		m.setToast(sError.Render("x "+msg.err.Error()), 5*time.Second)
		m.screen = screenMenu
	} else {
		dur := msg.duration
		if dur == 0 && !m.scanStartTime.IsZero() {
			dur = time.Since(m.scanStartTime).Round(time.Second)
		}
		m.addLog(fmt.Sprintf("Scan done: %d proxies in %s", len(msg.proxies), dur))
		m.setToast(sSuccess.Render(fmt.Sprintf("OK Found %d proxies", len(msg.proxies))), 3*time.Second)
		m.screen = screenScanResults
		m.cursor = 0
	}
	return m, nil
}

func (m tuiModel) handlePoolOperationComplete(msg poolOperationCompleteMsg) (tuiModel, tea.Cmd) {
	if len(msg.results) > 0 {
		seen := make(map[string]bool, len(m.scanResults)+len(msg.results))
		merged := make([]string, 0, len(m.scanResults)+len(msg.results))
		for _, result := range m.scanResults {
			if !seen[result] {
				seen[result] = true
				merged = append(merged, result)
			}
		}
		for _, result := range msg.results {
			if !seen[result] {
				seen[result] = true
				merged = append(merged, result)
			}
		}
		m.scanResults = merged
	} else {
		m.scanResults = msg.results
	}
	m.scanErr = msg.err
	if m.scanTotal <= 0 {
		m.scanTotal = 1
	}
	m.scanProgress = m.scanTotal
	m.scanHits = len(m.scanResults)
	m.scanMsgCh = nil
	m.scanCtx = nil
	m.scanCancel = nil
	if msg.err != nil {
		m.writeScanLogLine(fmt.Sprintf("[COMPLETE] %s failed: %v", msg.operationType, msg.err))
	} else {
		m.writeScanLogLine(fmt.Sprintf("[COMPLETE] %s done: %d items in %s", msg.operationType, len(m.scanResults), msg.duration))
		if msg.operationType == "scan_ips" || msg.operationType == "sni_scanner" || msg.operationType == "desync_scanner" {
			scanKind := msg.operationType
			if scanKind == "scan_ips" {
				scanKind = "ipscan"
			} else if scanKind == "sni_scanner" {
				scanKind = "sniscan"
			} else if scanKind == "desync_scanner" {
				scanKind = "desyncscan"
			}
			if path, err := saveScanOutputResults(m.app.DataDir, scanKind, m.scanResults, m.operationType); err != nil {
				m.addLog(fmt.Sprintf("Failed to save scan output: %v", err))
			} else {
				m.addLog(fmt.Sprintf("Saved scan output to %s", path))
			}
		}
		if msg.operationType == "desync_scanner" {
			pairs, snis, err := saveNativeDesyncArtifacts(m.app.DataDir, m.scanResults)
			if err != nil {
				m.addLog(fmt.Sprintf("Failed to save desync artifacts: %v", err))
			} else {
				m.addLog(fmt.Sprintf("Saved desync_pairs.json with %d pair(s); clean_snis.txt with %d SNI(s)", pairs, snis))
				state := loadDPIState(m.app.DataDir)
				pairsMap := loadDesyncPairs(m.app.DataDir)
				keys := sortedDPIMapKeys(pairsMap)
				if len(keys) > 0 && len(pairsMap[keys[0]]) > 0 {
					state.DpiSNI = keys[0]
					state.DpiIP = pairsMap[keys[0]][0]
					_ = saveDPIState(m.app.DataDir, state)
					m.dpiState = state
					m.addLog(fmt.Sprintf("Updated DPI target to %s / %s", state.DpiSNI, state.DpiIP))
				}
			}
		}
	}
	// append any newly discovered results to incremental output file
	m.appendNewScanResultsToFile()
	if msg.err != nil {
		m.addLog(fmt.Sprintf("%s failed: %v", msg.operationType, msg.err))
		m.setToast(sError.Render("x "+msg.err.Error()), 5*time.Second)
		m.screen = screenMenu
	} else {
		m.addLog(fmt.Sprintf("%s done: %d items", msg.operationType, len(msg.results)))
		m.setToast(sSuccess.Render(fmt.Sprintf("OK %s complete", msg.operationType)), 3*time.Second)
		m.screen = screenScanResults
		m.cursor = 0
	}
	return m, nil
}

func (m tuiModel) handleActionComplete(msg actionCompleteMsg) (tuiModel, tea.Cmd) {
	if msg.err != nil {
		m.addLog(fmt.Sprintf("%s failed: %v", msg.title, msg.err))
		m.setToast(sError.Render("x "+msg.err.Error()), 5*time.Second)
	} else {
		m.addLog(fmt.Sprintf("%s: %s", msg.title, msg.text))
		m.setToast(sSuccess.Render("OK "+msg.text), 4*time.Second)
	}
	return m, nil
}

// ------------------------------------------------------------
//  Command factories
// ------------------------------------------------------------

func (m tuiModel) cmdScanWithConfig(targets []string, cfg scanConfig, scanKind string) tea.Cmd {
	return func() tea.Msg {
		ports := cfg.Ports
		if len(ports) == 0 {
			ports = parsePorts(cfg.PortsString)
		}
		disc := cfg.Method
		if disc == "masscan" && !scanner.ToolAvailable("masscan") {
			disc = "direct"
		}
		if disc == "nmap" && !scanner.ToolAvailable("nmap") {
			disc = "direct"
		}
		conc := cfg.Concurrency
		if conc <= 0 {
			conc = 500
		}
		timeout := proxyScanTimeout(conc, cfg.LowBandwidth)
		opts := scanner.ProxyScanOptions{
			Ports:         ports,
			Discovery:     disc,
			Concurrency:   conc,
			Timeout:       timeout,
			TransferModel: strings.TrimSpace(cfg.TransferModel),
		}
		var proxies []string
		var err error
		start := time.Now()
		// The channel is already created on the model before this command runs
		cbCh := m.scanMsgCh
		// set log callback and proxy progress callback (forward all logs, non-blocking)
		m.app.Scanner.SetLogCallback(func(msg string) {
			select {
			case cbCh <- logMsg{msg}:
			default:
			}
		})
		m.app.Scanner.SetProxyProgressCallback(func(processed, total, hits int, currentIP string, totalIPs int) {
			// Map proxy progress into scanProgressMsg for the UI
			msg := scanProgressMsg{current: processed, total: total, hits: hits, startTime: start, currentIP: currentIP, totalIPs: totalIPs}
			select {
			case cbCh <- msg:
			default:
			}
		})
		// ensure callbacks are cleared
		defer func() {
			m.app.Scanner.SetLogCallback(nil)
			m.app.Scanner.SetProxyProgressCallback(nil)
		}()
		if scanKind == "socks5" {
			proxies, err = m.app.Scanner.ScanSOCKS5Proxies(targets, opts)
		} else {
			proxies, err = m.app.Scanner.ScanHTTPProxies(targets, opts)
		}
		if err != nil && disc != "direct" {
			if strings.Contains(strings.ToLower(err.Error()), "not found") {
				opts.Discovery = "direct"
				if scanKind == "socks5" {
					proxies, err = m.app.Scanner.ScanSOCKS5Proxies(targets, opts)
				} else {
					proxies, err = m.app.Scanner.ScanHTTPProxies(targets, opts)
				}
			}
		}
		if err != nil {
			return scanCompleteMsg{err: err}
		}
		for _, p := range proxies {
			ep := parseProxyEndpointFromResult(p)
			if ep == "" {
				continue
			}
			m.app.Router.AddRouteToCache("scan", ep, 500.0, true)
		}
		return scanCompleteMsg{proxies: proxies}
	}
}

func (m tuiModel) cmdPoolOperation(opType string, asnNetworks []string) tea.Cmd {
	if opType == "scan_ips" || opType == "sni_scanner" || opType == "desync_scanner" {
		cfg := m.scanConfig
		scannerInst := m.app.Scanner
		ch := m.scanMsgCh
		if ch == nil {
			ch = make(chan tea.Msg, 65536)
		}
		// save channel on model so Update can re-arm waiting for messages
		m.scanMsgCh = ch
		m.app.Scanner.SetTargetPorts(cfg.Ports)
		return tea.Batch(
			func() tea.Msg {
				t0 := time.Now()
				targets := asnNetworks
				if len(targets) == 0 {
					targets = cfg.Targets
				}

				ports := cfg.Ports
				if len(ports) == 0 {
					ports = []int{443, 2053, 2083, 2087, 2096, 8443}
				}
				endpointCount := len(targets) * len(ports)
				conc := cfg.Concurrency
				if conc <= 0 {
					conc = 250
				}
				timeout := scanTimeoutBudget(endpointCount, cfg.LowBandwidth)
				opts := scanner.IPScanOptions{
					Ports:                     ports,
					Concurrency:               conc,
					Timeout:                   timeout,
					EndpointCount:             endpointCount,
					LowBandwidth:              cfg.LowBandwidth,
					AdaptiveDomainConcurrency: cfg.AdaptiveDomainConcurrency,
				}
				if cfg.LowBandwidth {
					opts.AdaptiveDomainConcurrency = 1
				}
				if opType == "sni_scanner" || opType == "desync_scanner" {
					// SNI scanner uses tlsprobe hostnames for the TLS hostname probe path.
					// Prefer user-supplied domains from the inline SNI-source prompt,
					// falling back to the managed default list.
					domains := cfg.SNIDomains
					if len(domains) == 0 {
						domains = tlsprobe.GetDomains(m.app.DataDir)
					}
					opts.ProbeDomainsHTTPS = append([]string(nil), domains...)
					opts.ProbeDomainsHTTP = append([]string(nil), domains...)
				}

				scannerInst.SetLogCallback(func(msg string) {
					select {
					case ch <- logMsg{text: msg}:
					case <-time.After(50 * time.Millisecond):
					}
				})
				defer scannerInst.SetLogCallback(nil)

				start := time.Now()
				lastSent := 0
				lastAt := time.Time{}
				progressCb := func(processed, totalProbes, accepted int, currentIP string, totalIPs int) {
					if totalProbes <= 0 {
						return
					}
					now := time.Now()
					shouldSend := processed == totalProbes || processed-lastSent >= 25 || now.Sub(lastAt) >= 250*time.Millisecond
					if !shouldSend {
						return
					}
					msg := scanProgressMsg{current: processed, total: totalProbes, hits: accepted, startTime: start, currentIP: currentIP, totalIPs: totalIPs}
					select {
					case ch <- msg:
					case <-time.After(50 * time.Millisecond):
						// drop if unable to send within 50ms to avoid blocking scanner
					}
					lastSent = processed
					lastAt = now
				}

				if opType == "sni_scanner" || opType == "desync_scanner" {
					// SNI scanner uses tlsprobe runner with TLS probe domains.
					resCh := make(chan tlsprobe.ProbeResult, 1024)
					if len(targets) == 0 || len(opts.ProbeDomainsHTTPS) == 0 {
						// Nothing to probe: surface the reason instead of appearing to hang.
						reason := "no IP targets selected"
						if len(opts.ProbeDomainsHTTPS) == 0 {
							reason = "no SNI domains selected"
						}
						select {
						case ch <- logMsg{text: "[!] SNI scan aborted: " + reason}:
						default:
						}
						close(ch)
						return poolOperationCompleteMsg{operationType: opType, results: []string{"SNI scan aborted: " + reason}, duration: time.Since(t0)}
					}
					expandedIPs := len(tlsprobe.ExpandTargets(targets))
					if expandedIPs == 0 {
						expandedIPs = len(targets)
					}
					totalProbes := expandedIPs * len(ports) * len(opts.ProbeDomainsHTTPS)
					startScan := time.Now()
					select {
					case ch <- logMsg{text: fmt.Sprintf("[SNI] Expanded %d target range(s) to %d IP(s); ports=%d domains=%d total probes=%d", len(targets), expandedIPs, len(ports), len(opts.ProbeDomainsHTTPS), totalProbes)}:
					default:
					}
					select {
					case ch <- scanProgressMsg{current: 0, total: totalProbes, hits: 0, startTime: startScan, totalIPs: expandedIPs}:
					default:
					}
					runCtx := m.scanCtx
					if runCtx == nil {
						runCtx = context.Background()
					}
					go func() {
						probeCfg := tlsprobe.ScanConfig{
							Targets:     append([]string(nil), targets...),
							Hostnames:   append([]string(nil), opts.ProbeDomainsHTTPS...),
							Ports:       append([]int(nil), ports...),
							TimeoutSec:  float64(timeout.Seconds()),
							Concurrency: opts.Concurrency,
							StrictSNI:   cfg.SNIStrict,
							PauseFunc: func() bool {
								return scannerInst != nil && scannerInst.IsPaused()
							},
						}
						tlsprobe.RunScanContext(runCtx, probeCfg, resCh, nil)
					}()

					var sniResults []string
					processed := 0
					hits := 0
					certMatchCount := 0
					sniOKCount := 0
					tlsOnlyCount := 0
					failCount := 0
					timeoutCount := 0
					// Use the expanded IP count (not the CIDR count) so progress
					// reflects the actual number of probes.
					for pr := range resCh {
						processed++
						statusLabel := "FAIL"
						if pr.Success {
							statusLabel = "OK"
							hits++
						}
						kind := pr.ResultKind
						if kind == "" {
							kind = classifySNIResultKind(pr)
						}
						switch kind {
						case "cert-match":
							certMatchCount++
						case "sni-ok":
							sniOKCount++
						case "tls-only":
							tlsOnlyCount++
						default:
							failCount++
						}
						if isSNITimeout(pr) {
							timeoutCount++
						}
						text := fmt.Sprintf("%s %s:%d %s %s %dms %s %d", pr.Hostname, pr.IP, pr.Port, statusLabel, kind, int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus)
						// forward as logMsg for live UI
						select {
						case ch <- logMsg{text: text}:
						default:
						}

						// Write incremental CSV and failed/passed files so results are available in real-time
						if m.scanCSVPath != "" {
							csvLine := fmt.Sprintf("%s,%s:%d,%s,%s,%d,%s,%d,%t,%t,%q,%q", pr.Hostname, pr.IP, pr.Port, statusLabel, kind, int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus, pr.SNIAccepted, pr.CertMatchesSNI, pr.ServerHeader, pr.Error)
							_ = storage.AppendLine(m.scanCSVPath, csvLine)
						}

						if !pr.Success {
							if m.scanFailedPath != "" {
								_ = storage.AppendLine(m.scanFailedPath, text)
							}
						} else {
							// record passed ip:port to incremental passed file
							if m.scanOutputPath != "" {
								_ = storage.AppendLine(m.scanOutputPath, fmt.Sprintf("%s:%d", pr.IP, pr.Port))
							}
						}
						// forward progress update
						msg := scanProgressMsg{current: processed, total: totalProbes, hits: hits, startTime: startScan, currentIP: text, totalIPs: expandedIPs}
						select {
						case ch <- msg:
						default:
						}
						// Only keep successful results for the final menu list
						if pr.Success {
							sniResults = append(sniResults, text)
						}
					}
					summaryLine := fmt.Sprintf("[SNI-SUMMARY] ips=%d ports=%d domains=%d probes=%d processed=%d ok=%d cert-match=%d sni-ok=%d tls-only=%d fail=%d timeouts=%d",
						expandedIPs, len(ports), len(opts.ProbeDomainsHTTPS), totalProbes, processed, hits, certMatchCount, sniOKCount, tlsOnlyCount, failCount, timeoutCount)
					select {
					case ch <- logMsg{text: summaryLine}:
					default:
					}
					m.writeScanLogLine(summaryLine)
					close(ch)
					if err := runCtx.Err(); err != nil {
						return poolOperationCompleteMsg{operationType: opType, results: sniResults, err: err, duration: time.Since(t0)}
					}
					if len(sniResults) == 0 {
						sniResults = []string{"No responding IPs found"}
					}
					return poolOperationCompleteMsg{operationType: opType, results: sniResults, duration: time.Since(t0)}
				}

				results, err := scannerInst.ScanIPsWithProgress(targets, opts, progressCb)
				if err != nil {
					close(ch)
					return poolOperationCompleteMsg{operationType: opType, err: err, duration: time.Since(t0)}
				}
				if len(results) == 0 {
					results = []string{"No responding IPs found"}
				}
				close(ch)
				return poolOperationCompleteMsg{operationType: opType, results: results, duration: time.Since(t0)}
			},
			waitForScanMessage(ch),
		)
	}

	return func() tea.Msg {
		t0 := time.Now()
		var results []string

		switch opType {
		case "reload_pool":
			routesFile := filepath.Join(m.app.DataDir, "white_routes.txt")
			count, err := m.app.Router.LoadRoutes(routesFile)
			if err != nil {
				return poolOperationCompleteMsg{operationType: opType, err: err, duration: time.Since(t0)}
			}
			results = []string{fmt.Sprintf("Loaded %d routes", count)}

		case "inspect_pool":
			stats := m.app.Scanner.GetAllStats()
			for _, net := range asnNetworks {
				for ip := range stats {
					if strings.Contains(ip, net) || net == "all" {
						results = append(results, ip)
					}
				}
			}
			if len(results) == 0 {
				results = []string{"No IPs found for selected ASNs"}
			}
		}

		return poolOperationCompleteMsg{operationType: opType, results: results, duration: time.Since(t0)}
	}
}

func waitForScanMessage(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		if ch == nil {
			return nil
		}
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

func (m tuiModel) cmdProxyScan(targets []string, cfg scanConfig, scanKind string) tea.Cmd {
	scannerInst := m.app.Scanner
	ch := m.scanMsgCh
	if ch == nil {
		ch = make(chan tea.Msg, 65536)
	}
	m.scanMsgCh = ch

	return tea.Batch(
		func() tea.Msg {
			t0 := time.Now()

			ports := cfg.Ports
			if len(ports) == 0 {
				ports = parsePorts(cfg.PortsString)
			}
			disc := cfg.Method
			origMethod := disc

			if disc == "masscan" && !scanner.ToolAvailable("masscan") {
				disc = "direct"
			}
			if disc == "nmap" && !scanner.ToolAvailable("nmap") {
				disc = "direct"
			}

			// Log fallback if it occurred
			if origMethod != disc && origMethod != "direct" {
				ch <- logMsg{fmt.Sprintf("[!] %s not available - using direct scanning as fallback", strings.ToUpper(origMethod))}
			}
			conc := cfg.Concurrency
			if conc <= 0 {
				conc = 500
			}
			timeout := proxyScanTimeout(conc, cfg.LowBandwidth)
			opts := scanner.ProxyScanOptions{
				Ports:         ports,
				Discovery:     disc,
				Concurrency:   conc,
				Timeout:       timeout,
				TransferModel: strings.TrimSpace(cfg.TransferModel),
			}

			// Forward logs to UI with short timeout to avoid blocking scanner
			scannerInst.SetLogCallback(func(msg string) {
				select {
				case ch <- logMsg{text: msg}:
				case <-time.After(50 * time.Millisecond):
				}
			})
			defer scannerInst.SetLogCallback(nil)

			start := time.Now()
			lastSent := 0
			lastAt := time.Time{}

			// Set log callback (forward with timeout)
			scannerInst.SetLogCallback(func(msg string) {
				select {
				case ch <- logMsg{msg}:
				case <-time.After(50 * time.Millisecond):
				}
			})

			// Set progress callback
			progressCb := func(processed, total, hits int, currentIP string, totalIPs int) {
				if total <= 0 {
					return
				}
				now := time.Now()
				shouldSend := processed == total || processed-lastSent >= 10 || now.Sub(lastAt) >= 500*time.Millisecond
				if !shouldSend {
					return
				}
				msg := scanProgressMsg{current: processed, total: total, hits: hits, startTime: start, currentIP: currentIP, totalIPs: totalIPs}
				select {
				case ch <- msg:
				case <-time.After(50 * time.Millisecond):
				}
				lastSent = processed
				lastAt = now
			}
			scannerInst.SetProxyProgressCallback(progressCb)

			defer func() {
				scannerInst.SetLogCallback(nil)
				scannerInst.SetProxyProgressCallback(nil)
				close(ch)
			}()

			var proxies []string
			var err error
			if scanKind == "socks5" {
				proxies, err = scannerInst.ScanSOCKS5Proxies(targets, opts)
			} else {
				proxies, err = scannerInst.ScanHTTPProxies(targets, opts)
			}

			if err != nil {
				return scanCompleteMsg{proxies: nil, err: err, duration: time.Since(t0)}
			}
			return scanCompleteMsg{proxies: proxies, err: nil, duration: time.Since(t0)}
		},
		waitForScanMessage(ch),
	)
}

func (m tuiModel) cmdManagePool() tea.Cmd {
	return func() tea.Msg {
		stats := m.app.Scanner.GetAllStats()
		return actionCompleteMsg{title: "Pool", text: fmt.Sprintf("Pool size: %d endpoints", len(stats))}
	}
}

func (m tuiModel) cmdInspectIP(ip string) tea.Cmd {
	return func() tea.Msg {
		info, err := m.app.ASNEngine.Lookup(ip)
		if err != nil {
			return actionCompleteMsg{title: "IP Lookup", err: err}
		}
		text := fmt.Sprintf("ASN:%s  Name:%s  Type:%s  CIDR:%s", info.ASN, info.Name, info.Type, info.CIDR)
		return actionCompleteMsg{title: "IP Info", text: text}
	}
}

func (m tuiModel) cmdBridgeAction(action string) tea.Cmd {
	return func() tea.Msg {
		if m.app.PythonBridge == nil {
			return actionCompleteMsg{title: "Bridge", err: fmt.Errorf("python bridge unavailable")}
		}
		if err := m.app.PythonBridge.RunAction(action); err != nil {
			return actionCompleteMsg{title: "Bridge", err: err}
		}
		return actionCompleteMsg{title: "Bridge", text: action + " completed"}
	}
}

// ------------------------------------------------------------
//  Helpers
// ------------------------------------------------------------

func (m *tuiModel) pushScreen(next string) {
	m.prevScreen = m.screen
	m.screen = next
	m.screenChanged = true
	m.cursor = 0
}

func (m *tuiModel) goBack() {
	if m.prevScreen != "" {
		m.screen = m.prevScreen
	} else {
		m.screen = screenMenu
	}
	m.prevScreen = ""
	m.screenChanged = true
	m.cursor = 0
	m.menuCol = 0
	m.menuRow = 0
}

func (m *tuiModel) setupInput(placeholder string) {
	m.ti.SetValue("")
	m.ti.Placeholder = placeholder
	// Allow multiline input for pasting multiple IPs
	m.ti.CharLimit = 0 // unlimited for paste mode
	// reset paste confirm state when entering input
	m.pasteConfirm = false
	m.lastEnterTime = time.Time{} // reset Enter time tracking
	m.pasteBuffer = ""
	m.ti.Focus()
}

func (m *tuiModel) resetASNScreen(placeholder string) {
	m.selectedItems = make(map[int]bool)
	m.asnFiltered = m.asnList
	m.cursor = 0
	m.typingEnabled = true
	m.ti.SetValue("")
	m.ti.Placeholder = placeholder
	m.ti.Focus()
}

func (m *tuiModel) startOperation() {
	m.pushScreen(screenScanning)
	if m.scanCancel != nil {
		m.scanCancel()
	}
	m.scanCtx, m.scanCancel = context.WithCancel(context.Background())
	m.scanStartTime = time.Now()
	m.scanProgress = 0
	m.scanHits = 0
	m.scanResults = nil
	m.scanErr = nil
}

func (m *tuiModel) gotoScanMode(opType, kind string) {
	m.prevScreen = screenMenu
	m.screen = screenScanMode
	m.operationType = opType
	m.scanKind = kind
	m.scanConfig = scanConfig{TransferModel: "old"}
	m.cursor = 0
	m.selectedItems = make(map[int]bool)
}

func (m *tuiModel) addLog(text string) {
	entry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), text)
	m.logs = append(m.logs, entry)
	m.writeScanLogLine(entry)
}

func (m *tuiModel) writeScanLogLine(line string) {
	if m == nil || m.scanLogPath == "" {
		return
	}
	m.scanLogMu.Lock()
	defer m.scanLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(m.scanLogPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(m.scanLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

func (m *tuiModel) startScanLogFile(scanKind string, targets []string, ports []int, concurrency int, timeout time.Duration) string {
	dataDir := "."
	if m != nil && m.app != nil && m.app.DataDir != "" {
		dataDir = m.app.DataDir
	}
	logDir := whitednsLogsDir(dataDir)
	_ = os.MkdirAll(logDir, 0o755)
	stamp := time.Now().Format("20060102-150405")
	path := filepath.Join(logDir, fmt.Sprintf("scan-%s-%s.txt", scanKind, stamp))
	if absPath, err := filepath.Abs(path); err == nil {
		path = absPath
	}
	m.scanLogPath = path
	m.writeScanLogLine(fmt.Sprintf("[START] kind=%s targets=%d ports=%d concurrency=%d timeout=%s", scanKind, len(targets), len(ports), concurrency, timeout))

	transferPath := filepath.Join(logDir, fmt.Sprintf("transfer-%s-%s.txt", scanKind, stamp))
	if absTransfer, err := filepath.Abs(transferPath); err == nil {
		transferPath = absTransfer
	}
	m.transferLogPath = transferPath
	_ = storage.AtomicWriteText(transferPath, fmt.Sprintf("# Transfer benchmark log\n# kind: %s\n# section: throughput latency tags\n\n", scanKind))
	m.writeScanLogLine(fmt.Sprintf("[TRANSFER] log file: %s", transferPath))

	// Log targets with proper spacing - one per line for readability
	m.writeScanLogLine(fmt.Sprintf("[TARGETS] %d total:", len(targets)))
	for i, target := range targets {
		m.writeScanLogLine(fmt.Sprintf("  [%d] %s", i+1, target))
	}

	m.writeScanLogLine(fmt.Sprintf("[PORTS] %v", ports))

	// create incremental scan output file so partial results are saved in real-time
	if err := os.MkdirAll(logDir, 0o755); err == nil {
		stamp := time.Now().Format("20060102-150405")
		outPath := filepath.Join(logDir, fmt.Sprintf("passed-%s-%s.txt", scanKind, stamp))
		if absOut, err := filepath.Abs(outPath); err == nil {
			outPath = absOut
		}
		header := fmt.Sprintf("# Passed endpoints\n# kind: %s\n# partial: true\n\n", scanKind)
		// create initial file (overwrite if somehow exists)
		_ = os.WriteFile(outPath, []byte(header), 0o644)
		m.scanOutputPath = outPath
		m.scanDomainPassPath = ""

		// if SNI scanner, also prepare failed and CSV incremental files
		if scanKind == "sni_scanner" || scanKind == "desync_scanner" || m.operationType == "sni_scanner" || m.operationType == "desync_scanner" {
			failedPath := filepath.Join(logDir, fmt.Sprintf("failed-%s-%s.txt", scanKind, stamp))
			if absFailed, err := filepath.Abs(failedPath); err == nil {
				failedPath = absFailed
			}
			_ = os.WriteFile(failedPath, []byte(fmt.Sprintf("# Failed endpoints\n# kind: %s\n# partial: true\n\n", scanKind)), 0o644)
			m.scanFailedPath = failedPath

			csvPath := filepath.Join(logDir, fmt.Sprintf("sni-%s-%s.csv", scanKind, stamp))
			if absCSV, err := filepath.Abs(csvPath); err == nil {
				csvPath = absCSV
			}
			_ = os.WriteFile(csvPath, []byte("hostname,ipport,status,result_kind,latency_ms,tls_version,http_status,sni_accepted,cert_matches_sni,server_header,error\n"), 0o644)
			m.scanCSVPath = csvPath
		} else if scanKind == "ipscan" {
			domainPassPath := filepath.Join(logDir, fmt.Sprintf("domain-passes-%s-%s.txt", scanKind, stamp))
			if absDomainPass, err := filepath.Abs(domainPassPath); err == nil {
				domainPassPath = absDomainPass
			}
			domainHeader := fmt.Sprintf("# Domain passes for passed endpoints\n# kind: %s\n# format: ip:port | passed/total | domain1,domain2\n\n", scanKind)
			if err := os.WriteFile(domainPassPath, []byte(domainHeader), 0o644); err != nil {
				m.writeScanLogLine(fmt.Sprintf("[OUTPUT] domain pass create failed: %v", err))
				if fallbackErr := storage.AppendLine(domainPassPath, strings.TrimRight(domainHeader, "\n")); fallbackErr != nil {
					m.writeScanLogLine(fmt.Sprintf("[OUTPUT] domain pass fallback failed: %v", fallbackErr))
				}
			}
			m.scanDomainPassPath = domainPassPath
			m.writeScanLogLine(fmt.Sprintf("[OUTPUT] domain pass output: %s", domainPassPath))
		}
		// reset tracking
		m.scanOutputMu.Lock()
		m.scanOutputWritten = make(map[string]bool)
		m.scanDomainPassWritten = make(map[string]bool)
		m.scanOutputMu.Unlock()
		m.writeScanLogLine(fmt.Sprintf("[OUTPUT] incremental output: %s", outPath))
	}
	return path
}

// appendNewScanResultsToFile appends any newly discovered scan results
// into the incremental output file (created at scan start). Duplicates
// are tracked in memory to avoid repeated writes.
func (m *tuiModel) appendNewScanResultsToFile() {
	if m.scanOutputPath == "" {
		return
	}
	m.scanOutputMu.Lock()
	defer m.scanOutputMu.Unlock()
	if len(m.scanResults) == 0 {
		return
	}
	for _, ep := range m.scanResults {
		if ep == "" {
			continue
		}
		if m.scanOutputWritten[ep] {
			continue
		}

		outEp := ep
		if m.operationType != "sni_scanner" && m.operationType != "desync_scanner" {
			// strip tags and extract just IP:port for the passed IP file
			if parts := strings.Fields(ep); len(parts) > 1 && strings.Contains(parts[1], ":") {
				outEp = parts[1] // handles "http 1.2.3.4:80 lat=..."
			} else if len(parts) > 0 && strings.Contains(parts[0], ":") {
				outEp = parts[0]
			}
			if err := storage.AppendLine(m.scanOutputPath, outEp); err != nil {
				m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append failed: %v", err))
				// don't mark as written on error
				continue
			}
		} else {
			// SNI scanner: separate passed and failed into different files and write CSV
			passed := strings.Contains(strings.ToUpper(ep), " OK ") || strings.Contains(strings.ToUpper(ep), " OK")
			failed := strings.Contains(strings.ToUpper(ep), " FAIL ") || strings.Contains(strings.ToUpper(ep), " FAIL")

			// parse components for CSV
			parts := strings.Fields(ep)
			hostname := ""
			ipport := ""
			status := "UNKNOWN"
			kind := ""
			latency := ""
			tlsv := ""
			httpst := ""
			if len(parts) >= 1 {
				hostname = parts[0]
			}
			if len(parts) >= 2 {
				ipport = parts[1]
			}
			if len(parts) >= 3 {
				status = parts[2]
			}
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

			// write passed to incremental passed file
			if passed {
				// prefer ip:port only in passed file
				epOut := ipport
				if epOut == "" {
					epOut = outEp
				}
				if err := storage.AppendLine(m.scanOutputPath, epOut); err != nil {
					m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append passed failed: %v", err))
					continue
				}
			}

			// write failed entries to failed file (so they don't appear in UI)
			if failed && m.scanFailedPath != "" {
				if err := storage.AppendLine(m.scanFailedPath, ep); err != nil {
					m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append failed file failed: %v", err))
				}
			}

			// append CSV line if csv path available
			if m.scanCSVPath != "" {
				csvLine := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,,,,", hostname, ipport, status, kind, latency, tlsv, httpst)
				if err := storage.AppendLine(m.scanCSVPath, csvLine); err != nil {
					m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append csv failed: %v", err))
				}
			}
		}

		m.scanOutputWritten[ep] = true
	}
}

func saveNativeDesyncArtifacts(dataDir string, results []string) (pairCount int, sniCount int, err error) {
	if dataDir == "" {
		dataDir = "."
	}
	pairs := make(map[string][]string)
	seen := make(map[string]map[string]struct{})

	for _, line := range results {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, " OK ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sni := strings.TrimSpace(parts[0])
		ipport := strings.TrimSpace(parts[1])
		if sni == "" || ipport == "" {
			continue
		}
		host := ipport
		if h, _, splitErr := net.SplitHostPort(ipport); splitErr == nil && h != "" {
			host = h
		}
		if net.ParseIP(host) == nil {
			continue
		}
		if _, ok := seen[sni]; !ok {
			seen[sni] = make(map[string]struct{})
		}
		if _, ok := seen[sni][host]; ok {
			continue
		}
		seen[sni][host] = struct{}{}
		pairs[sni] = append(pairs[sni], host)
	}

	if len(pairs) == 0 {
		return 0, 0, nil
	}

	for sni := range pairs {
		sort.Strings(pairs[sni])
		pairCount += len(pairs[sni])
	}
	keys := sortedDPIMapKeys(pairs)
	sniCount = len(keys)

	pairsPath := filepath.Join(dataDir, "desync_pairs.json")
	if err := storage.AtomicWriteJSON(pairsPath, pairs); err != nil {
		return 0, 0, err
	}

	cleanPath := filepath.Join(dataDir, "clean_snis.txt")
	if err := storage.AtomicWriteText(cleanPath, strings.Join(keys, "\n")+"\n"); err != nil {
		return 0, 0, err
	}

	return pairCount, sniCount, nil
}

func (m *tuiModel) appendTransferLogLineFromScanLog(line string) {
	if m == nil || m.transferLogPath == "" {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if !strings.Contains(line, "KB/s") && !strings.Contains(line, "lat=") && !strings.Contains(line, "↓") && !strings.Contains(line, "↑") && !strings.Contains(line, "up") && !strings.Contains(line, "down") && !strings.Contains(line, "[telegram]") && !strings.Contains(line, "[chatgpt]") && !strings.Contains(line, "[instagram]") && !strings.Contains(line, "[workers]") && !strings.Contains(line, "[pages]") && !strings.Contains(line, "[psiphon]") {
		return
	}
	m.transferLogMu.Lock()
	defer m.transferLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(m.transferLogPath), 0o755); err != nil {
		return
	}
	if err := storage.AppendLine(m.transferLogPath, line); err != nil {
		m.writeScanLogLine(fmt.Sprintf("[TRANSFER] append failed: %v", err))
	}
}

func (m *tuiModel) appendDomainPassLineFromScanLog(line string) {
	if m == nil || m.scanDomainPassPath == "" {
		return
	}
	ipPort, domains, passedCount, totalDomains, ok := parseDomainPassFromScannerLog(line)
	if !ok || ipPort == "" || len(domains) == 0 {
		return
	}
	if passedCount < 0 {
		passedCount = 0
	}
	if totalDomains <= 0 {
		totalDomains = 9
	}
	if passedCount == 0 {
		passedCount = len(domains)
	}

	record := fmt.Sprintf("%s | %d/%d | %s", ipPort, passedCount, totalDomains, strings.Join(domains, ","))

	m.scanOutputMu.Lock()
	if m.scanDomainPassWritten == nil {
		m.scanDomainPassWritten = make(map[string]bool)
	}
	alreadyRecorded := m.scanDomainPassWritten[record]
	if !alreadyRecorded {
		m.scanDomainPassWritten[record] = true
	}
	if m.scanOutputWritten == nil {
		m.scanOutputWritten = make(map[string]bool)
	}
	newAccept := !m.scanOutputWritten[ipPort]
	if newAccept {
		m.scanOutputWritten[ipPort] = true
	}
	m.scanOutputMu.Unlock()

	if !alreadyRecorded {
		if err := storage.AppendLine(m.scanDomainPassPath, record); err != nil {
			m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append domain pass failed: %v", err))
		}
	}

	// [ACCEPT] log lines are the authoritative signal that this endpoint
	// passed - record it for the live results view and the passed-ipscan
	// output file right away (mirrors the SNI/desync incremental write).
	if newAccept {
		if len(m.scanResults) == 0 || m.scanResults[len(m.scanResults)-1] != ipPort {
			m.scanResults = append(m.scanResults, ipPort)
		}
		if m.scanOutputPath != "" {
			if err := storage.AppendLine(m.scanOutputPath, ipPort); err != nil {
				m.writeScanLogLine(fmt.Sprintf("[OUTPUT] append failed: %v", err))
			}
		}
	}
}

func parseDomainPassFromScannerLog(line string) (string, []string, int, int, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "[ACCEPT]") {
		return "", nil, 0, 0, false
	}

	idx := strings.Index(line, "[ACCEPT]")
	if idx < 0 {
		return "", nil, 0, 0, false
	}
	body := strings.TrimSpace(line[idx+len("[ACCEPT]"):])
	if body == "" {
		return "", nil, 0, 0, false
	}

	parts := strings.Fields(body)
	if len(parts) == 0 {
		return "", nil, 0, 0, false
	}
	ipPort := strings.TrimSpace(parts[0])
	if ipPort == "" || !strings.Contains(ipPort, ":") {
		return "", nil, 0, 0, false
	}

	passedCount := 0
	totalDomains := 0
	for _, token := range parts {
		if strings.HasPrefix(token, "domains=") {
			rawDomains := strings.TrimPrefix(token, "domains=")
			var tested, total int
			if _, err := fmt.Sscanf(rawDomains, "%d/%d", &tested, &total); err == nil {
				totalDomains = total
			}
		}
		if strings.HasPrefix(token, "domain_score=") {
			rawScore := strings.TrimPrefix(token, "domain_score=")
			var score int
			if _, err := fmt.Sscanf(rawScore, "%d", &score); err == nil {
				passedCount = score
			}
		}
	}

	passIdx := strings.Index(body, "passed=[")
	if passIdx < 0 {
		return "", nil, passedCount, totalDomains, false
	}
	raw := body[passIdx+len("passed=["):]
	end := strings.Index(raw, "]")
	if end < 0 {
		return "", nil, passedCount, totalDomains, false
	}
	raw = strings.TrimSpace(raw[:end])
	if raw == "" {
		return "", nil, passedCount, totalDomains, false
	}

	seen := make(map[string]struct{})
	domains := make([]string, 0, 8)
	for _, d := range strings.Split(raw, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, exists := seen[d]; exists {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	if len(domains) == 0 {
		return "", nil, passedCount, totalDomains, false
	}

	sort.Strings(domains)
	return ipPort, domains, passedCount, totalDomains, true
}

func parseProxyEndpointFromResult(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}
	// New proxy format: "http 1.2.3.4:8080 lat=... [tag]"
	if len(parts) >= 2 && strings.Contains(parts[1], ":") {
		return parts[1]
	}
	// Backward-compatible legacy endpoint-only format.
	if strings.Contains(parts[0], ":") {
		return parts[0]
	}
	return ""
}

func classifySNIResultKind(pr tlsprobe.ProbeResult) string {
	if pr.CertMatchesSNI {
		return "cert-match"
	}
	if pr.SNIAccepted {
		return "sni-ok"
	}
	if pr.Success {
		return "tls-only"
	}
	return "fail"
}

func isSNITimeout(pr tlsprobe.ProbeResult) bool {
	errText := strings.ToLower(pr.Error)
	return strings.Contains(errText, "timeout") ||
		strings.Contains(errText, "deadline") ||
		strings.Contains(errText, "i/o timeout")
}

func scanTimeoutBudget(endpointCount int, lowBandwidth bool) time.Duration {
	var budget time.Duration
	switch {
	case endpointCount >= 1000000:
		budget = 1500 * time.Millisecond
	case endpointCount >= 100000:
		budget = 2 * time.Second
	case endpointCount >= 10000:
		budget = 2500 * time.Millisecond
	case endpointCount >= 1000:
		budget = 3 * time.Second
	default:
		budget = 4 * time.Second
	}
	if lowBandwidth {
		// High-latency links need a far more forgiving per-endpoint budget so
		// slow-but-usable hosts are not dropped. Floor it at 12s.
		budget *= 4
		if budget < 12*time.Second {
			budget = 12 * time.Second
		}
	}
	return budget
}

// proxyScanTimeout returns the per-endpoint verification timeout for proxy
// scans. Low-bandwidth mode uses a generous fixed budget; the wave verifier
// scales its sub-timeouts from this value (see waveTimeouts in proxy_scan.go).
func proxyScanTimeout(conc int, lowBandwidth bool) time.Duration {
	if lowBandwidth {
		return 25 * time.Second
	}
	timeout := time.Duration(6+conc/500) * time.Second
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout
}

func (m *tuiModel) setToast(text string, dur time.Duration) {
	m.toast = text
	m.toastExpiry = time.Now().Add(dur)
}

func (m tuiModel) toastActive() bool {
	return time.Now().Before(m.toastExpiry)
}

// recentLogs returns the last n log lines, each clamped to maxW chars.
func (m tuiModel) recentLogs(n, maxW int) []string {
	start := len(m.logs) - n
	if start < 0 {
		start = 0
	}
	lines := make([]string, 0, n)
	for i := start; i < len(m.logs); i++ {
		l := m.logs[i]
		if len(l) > maxW {
			l = l[:maxW-1] + "..."
		}
		lines = append(lines, sDim.Render("  - "+l))
	}
	return lines
}

// ------------------------------------------------------------
//  Port parser
// ------------------------------------------------------------

func parsePorts(portStr string) []int {
	if portStr == "" {
		return []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rng := strings.SplitN(part, "-", 2)
			s, _ := strconv.Atoi(strings.TrimSpace(rng[0]))
			e, _ := strconv.Atoi(strings.TrimSpace(rng[1]))
			for p := s; p <= e; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	if len(ports) == 0 {
		return []int{80, 443, 8080}
	}
	sort.Ints(ports)
	return ports
}

// compressPorts converts a list of ports into a compact range string,
// e.g. [80,81,82,443,8000,8001] -> "80-82,443,8000-8001"
func compressPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	uniq := make(map[int]bool)
	for _, p := range ports {
		uniq[p] = true
	}
	var ps []int
	for p := range uniq {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	var parts []string
	start := ps[0]
	prev := ps[0]
	for i := 1; i < len(ps); i++ {
		cur := ps[i]
		if cur == prev+1 {
			prev = cur
			continue
		}
		if start == prev {
			parts = append(parts, fmt.Sprintf("%d", start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
		}
		start = cur
		prev = cur
	}
	// finish last
	if start == prev {
		parts = append(parts, fmt.Sprintf("%d", start))
	} else {
		parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
	}
	return strings.Join(parts, ",")
}
