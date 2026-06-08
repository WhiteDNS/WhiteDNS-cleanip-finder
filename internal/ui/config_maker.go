package ui

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"whitedns-go/internal/bundledata"
	"whitedns-go/internal/storage"

	tea "github.com/charmbracelet/bubbletea"
)

const screenConfigMaker = "config_maker"

const (
	cmStepMain       = 0
	cmStepSourceMode = 10
	cmStepSourceText = 11
	cmStepSourcePick = 12
	cmStepTargetMode = 20
	cmStepTargetText = 21
	cmStepTargetPick = 22
	cmStepOutputPath = 30
)

var configMakerURIRe = regexp.MustCompile(`(?i)(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s]+`)

func (m *tuiModel) initConfigMaker() {
	m.tiStep = cmStepMain
	m.stepData = make(map[string]string)
	m.cursor = 0
	m.ti.Blur()
	m.ti.SetValue("")
	m.ti.Placeholder = ""
}

func (m tuiModel) viewConfigMaker(w, h int) string {
	inner := w - 6
	visibleRows := h - 10
	if visibleRows < 3 {
		visibleRows = 3
	}
	var body strings.Builder

	switch m.tiStep {
	case cmStepMain:
		items := []string{
			"Rewrite configs (add/replace endpoint using IP:port target list)",
			"Reverse extract IP:port from proxy configs (save to file)",
			"Reverse extract IP:port from proxy configs (preview only)",
		}
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepSourceMode:
		items := []string{
			"Paste CONFIG text",
			"Choose CONFIG TXT file from config maker folder",
			"Enter CONFIG TXT file path",
		}
		body.WriteString(sDim.Render("  You are adding: CONFIG input\n\n"))
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE MODE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepSourceText:
		if m.stepData["cm_source_mode"] == "path" {
			body.WriteString(sDim.Render("  You are adding: CONFIG input\n"))
			body.WriteString(sDim.Render("  Enter CONFIG TXT file path\n\n"))
		} else {
			body.WriteString(sDim.Render("  You are adding: CONFIG input\n"))
			body.WriteString(sDim.Render("  Paste CONFIG text (config lines)\n\n"))
		}
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE INPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")

	case cmStepSourcePick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		items := make([]string, 0, len(files)+1)
		for _, f := range files {
			items = append(items, filepath.Base(f))
		}
		items = append(items, "Enter custom CONFIG TXT file path")
		body.WriteString(sDim.Render("  You are adding: CONFIG input\n\n"))
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		if len(files) == 0 {
			body.WriteString("\n" + sWarn.Render("  No TXT files found in config maker folder"))
		}
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE FILE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepTargetMode:
		items := []string{
			"Paste IP:port target list",
			"Choose IP:port targets TXT file from config maker folder",
			"Enter IP:port targets TXT file path",
		}
		body.WriteString(sDim.Render("  You are adding: IP:port targets\n\n"))
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET MODE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepTargetText:
		if m.stepData["cm_target_mode"] == "path" {
			body.WriteString(sDim.Render("  You are adding: IP:port targets\n"))
			body.WriteString(sDim.Render("  Enter IP:port targets TXT file path\n\n"))
		} else {
			body.WriteString(sDim.Render("  You are adding: IP:port targets\n"))
			body.WriteString(sDim.Render("  Paste IP:port target list\n\n"))
		}
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET INPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")

	case cmStepTargetPick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		items := make([]string, 0, len(files)+1)
		for _, f := range files {
			items = append(items, filepath.Base(f))
		}
		items = append(items, "Enter custom IP:port targets TXT file path")
		body.WriteString(sDim.Render("  You are adding: IP:port targets\n\n"))
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		if len(files) == 0 {
			body.WriteString("\n" + sWarn.Render("  No TXT files found in config maker folder"))
		}
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET FILE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepOutputPath:
		def := m.stepData["cm_output_default"]
		body.WriteString(sDim.Render("  Output TXT file path\n\n"))
		body.WriteString(sDim.Render("  Default: " + def + "\n\n"))
		body.WriteString(sDim.Render("  Tip: filename-only path is saved in config maker folder\n\n"))
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - OUTPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")
	}

	panel := panelStyle(cBorderActive).Width(inner).Render(sHeader.Render(" CONFIG MAKER "))
	return panel + "\n\n" + sDim.Render("Esc back")
}

func (m tuiModel) handleConfigMakerScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		if m.tiStep == cmStepSourceText || m.tiStep == cmStepTargetText || m.tiStep == cmStepOutputPath {
			m.ti, _ = m.ti.Update(msg)
		}
		return m, nil
	}

	s := k.String()
	if s == "q" || s == "esc" {
		switch m.tiStep {
		case cmStepMain:
			m.goBack()
		case cmStepSourceMode:
			m.tiStep = cmStepMain
			m.cursor = 0
		case cmStepSourceText, cmStepSourcePick:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
			m.ti.Blur()
		case cmStepTargetMode:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		case cmStepTargetText, cmStepTargetPick:
			m.tiStep = cmStepTargetMode
			m.cursor = 0
			m.ti.Blur()
		case cmStepOutputPath:
			if m.stepData["cm_flow"] == "rewrite" {
				m.tiStep = cmStepTargetMode
			} else {
				m.tiStep = cmStepSourceMode
			}
			m.cursor = 0
			m.ti.Blur()
		}
		return m, nil
	}

	if s == "0" && m.tiStep == cmStepMain {
		m.goBack()
		return m, nil
	}

	switch m.tiStep {
	case cmStepMain:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.stepData = map[string]string{"cm_flow": "rewrite"}
			case 1:
				m.stepData = map[string]string{"cm_flow": "reverse_save"}
			default:
				m.stepData = map[string]string{"cm_flow": "reverse_preview"}
			}
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		}
		return m, nil

	case cmStepSourceMode:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "paste"
				m.setupInput("Paste CONFIG text")
			case 1:
				m.tiStep = cmStepSourcePick
				m.stepData["cm_source_mode"] = "pick"
				m.stepData["cm_files"] = configMakerEncodeList(configMakerListTXTFiles(configMakerSupportDir(m)))
				m.cursor = 0
				m.ti.Blur()
			case 2:
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "path"
				m.setupInput("Enter CONFIG TXT file path")
			}
		}
		return m, nil

	case cmStepSourcePick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		itemsCount := len(files) + 1 // +1 for custom path
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			if m.cursor >= len(files) {
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "path"
				m.setupInput("Enter CONFIG TXT file path")
				return m, nil
			}
			data := configMakerReadFile(files[m.cursor])
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Selected file is empty"), 3*time.Second)
				return m, nil
			}
			m.stepData["cm_source_text"] = data
			return m.advanceConfigMakerAfterSource()
		}
		return m, nil

	case cmStepSourceText:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		raw := strings.TrimSpace(m.ti.Value())
		if raw == "" {
			m.setToast(sWarn.Render("No source provided"), 3*time.Second)
			return m, nil
		}
		if m.stepData["cm_source_mode"] == "path" {
			data := configMakerReadFile(raw)
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Source file not found or empty"), 3*time.Second)
				return m, nil
			}
			m.stepData["cm_source_text"] = data
		} else {
			m.stepData["cm_source_text"] = raw
		}
		return m.advanceConfigMakerAfterSource()

	case cmStepTargetMode:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "paste"
				m.setupInput("Paste IP:port target list")
			case 1:
				m.tiStep = cmStepTargetPick
				m.stepData["cm_target_mode"] = "pick"
				m.stepData["cm_files"] = configMakerEncodeList(configMakerListTXTFiles(configMakerSupportDir(m)))
				m.cursor = 0
				m.ti.Blur()
			case 2:
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "path"
				m.setupInput("Enter IP:port targets TXT file path")
			}
		}
		return m, nil

	case cmStepTargetPick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		itemsCount := len(files) + 1 // +1 for custom path
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			if m.cursor >= len(files) {
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "path"
				m.setupInput("Enter IP:port targets TXT file path")
				return m, nil
			}
			data := configMakerReadFile(files[m.cursor])
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Selected file is empty"), 3*time.Second)
				return m, nil
			}
			m.stepData["cm_target_text"] = data
			m.tiStep = cmStepOutputPath
			m.stepData["cm_output_default"] = filepath.Join(configMakerOutputDir(m), "rewritten_configs.txt")
			m.setupInput("Enter output path or leave empty for default")
			return m, nil
		}
		return m, nil

	case cmStepTargetText:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		raw := strings.TrimSpace(m.ti.Value())
		if raw == "" {
			m.setToast(sWarn.Render("No targets provided"), 3*time.Second)
			return m, nil
		}
		if m.stepData["cm_target_mode"] == "path" {
			data := configMakerReadFile(raw)
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Targets file not found or empty"), 3*time.Second)
				return m, nil
			}
			m.stepData["cm_target_text"] = data
		} else {
			m.stepData["cm_target_text"] = raw
		}
		m.tiStep = cmStepOutputPath
		m.stepData["cm_output_default"] = filepath.Join(configMakerSupportDir(m), "rewritten_configs.txt")
		m.setupInput("Enter output path or leave empty for default")
		return m, nil

	case cmStepOutputPath:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		out := strings.TrimSpace(m.ti.Value())
		if out == "" {
			out = m.stepData["cm_output_default"]
		}
		if m.stepData["cm_flow"] == "rewrite" {
			return m.applyConfigMakerRewriteToPath(m.stepData["cm_source_text"], m.stepData["cm_target_text"], out)
		}
		return m.applyConfigMakerReverse(m.stepData["cm_source_text"], true, out)
	}

	return m, nil
}

func configMakerRenderList(items []string, cursor, visibleRows int) string {
	if len(items) == 0 {
		return sDim.Render("  (no items)")
	}
	start := 0
	if cursor >= visibleRows {
		start = cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(items) {
		end = len(items)
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(items) {
		cursor = len(items) - 1
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		if i == cursor {
			rows.WriteString(sSelected.Render(items[i]) + "\n")
		} else {
			rows.WriteString(sNormal.Render(items[i]) + "\n")
		}
	}
	if len(items) > visibleRows {
		rows.WriteString(sDim.Render(fmt.Sprintf("  [%d/%d]", cursor+1, len(items))) + "\n")
	}
	return rows.String()
}

func (m tuiModel) advanceConfigMakerAfterSource() (tuiModel, tea.Cmd) {
	flow := m.stepData["cm_flow"]
	source := m.stepData["cm_source_text"]
	if flow == "rewrite" {
		m.tiStep = cmStepTargetMode
		m.ti.Blur()
		return m, nil
	}
	if flow == "reverse_preview" {
		return m.applyConfigMakerReverse(source, false, "")
	}
	m.tiStep = cmStepOutputPath
	m.stepData["cm_output_default"] = filepath.Join(configMakerOutputDir(m), "extracted_ips.txt")
	m.setupInput("Enter output path or leave empty for default")
	return m, nil
}

func (m tuiModel) applyConfigMakerRewriteToPath(configText, targetText, outPath string) (tuiModel, tea.Cmd) {
	configs := extractConfigMakerConfigs(configText)
	targets := extractConfigMakerTargets(targetText)
	if len(configs) == 0 {
		m.setToast(sWarn.Render("No configs found"), 3*time.Second)
		return m, nil
	}
	if len(targets) == 0 {
		m.setToast(sWarn.Render("No valid IP:port targets found"), 3*time.Second)
		return m, nil
	}

	blocks := rewriteConfigMakerConfigs(configs, targets)
	saved, err := configMakerSaveTextOutput(outPath, blocks, configMakerOutputDir(m))
	if err != nil {
		m.setToast(sError.Render("x Failed to save rewritten configs"), 4*time.Second)
		m.addLog(fmt.Sprintf("Config maker rewrite failed: %v", err))
		return m, nil
	}

	m.scanResults = previewStrings(blocks, 25)
	m.scanErr = nil
	m.operationType = "config_maker"
	m.scanKind = "config_maker"
	m.addLog(fmt.Sprintf("Saved %d rewritten config(s) to %s", len(blocks), saved))
	m.setToast(sSuccess.Render("OK Configs rewritten"), 4*time.Second)
	m.screen = screenScanResults
	m.cursor = 0
	m.initConfigMaker()
	return m, nil
}

func (m tuiModel) applyConfigMakerReverse(configText string, save bool, outPath string) (tuiModel, tea.Cmd) {
	ips := extractConfigMakerIPs(configText)
	if len(ips) == 0 {
		m.setToast(sWarn.Render("No IP:port endpoints found"), 4*time.Second)
		return m, nil
	}

	if save {
		saved, err := configMakerSaveTextOutput(outPath, ips, configMakerOutputDir(m))
		if err != nil {
			m.setToast(sError.Render("x Failed to save extracted IPs"), 4*time.Second)
			m.addLog(fmt.Sprintf("Config maker reverse failed: %v", err))
			return m, nil
		}
		m.addLog(fmt.Sprintf("Saved %d extracted IP(s) to %s", len(ips), saved))
	} else {
		m.addLog(fmt.Sprintf("Extracted %d endpoint(s)", len(ips)))
	}

	m.scanResults = previewStrings(ips, 25)
	m.scanErr = nil
	m.operationType = "config_maker"
	m.scanKind = "config_maker"
	m.setToast(sSuccess.Render("OK Extraction complete"), 4*time.Second)
	m.screen = screenScanResults
	m.cursor = 0
	m.initConfigMaker()
	return m, nil
}

func configMakerReadFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if data, err := os.ReadFile(path); err == nil {
		return string(data)
	}
	if data, err := os.ReadFile(filepath.Clean(path)); err == nil {
		return string(data)
	}
	return ""
}

func configMakerSupportDir(m tuiModel) string {
	if m.app != nil && m.app.DataDir != "" {
		if dir, err := bundledata.EnsureConfigMakerDataDir(m.app.DataDir); err == nil && strings.TrimSpace(dir) != "" {
			return dir
		}
		candidate := filepath.Join(m.app.DataDir, "config maker")
		if err := os.MkdirAll(candidate, 0o755); err == nil {
			return candidate
		}
	}
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "config maker")
		if err := os.MkdirAll(candidate, 0o755); err == nil {
			return candidate
		}
		return wd
	}
	return "."
}

func whitednsLogsDir(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, "whitedns logs")
}

func configMakerOutputDir(m tuiModel) string {
	if m.app != nil && m.app.DataDir != "" {
		return whitednsLogsDir(m.app.DataDir)
	}
	return whitednsLogsDir("")
}

func configMakerListTXTFiles(folder string) []string {
	if strings.TrimSpace(folder) == "" {
		return nil
	}
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return nil
	}

	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.EqualFold(filepath.Ext(name), ".txt") {
			out = append(out, filepath.Join(folder, name))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(filepath.Base(out[i])) < strings.ToLower(filepath.Base(out[j]))
	})
	return out
}

func configMakerEncodeList(items []string) string {
	return strings.Join(items, "\n")
}

func configMakerDecodeList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func configMakerSaveTextOutput(outputPath string, lines []string, baseDir string) (string, error) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return "", fmt.Errorf("empty output path")
	}
	if !filepath.IsAbs(outputPath) {
		// Treat relative output as local to the provided base directory.
		if strings.TrimSpace(baseDir) != "" {
			outputPath = filepath.Join(baseDir, outputPath)
		} else if abs, err := filepath.Abs(outputPath); err == nil {
			outputPath = abs
		}
	}
	if !strings.EqualFold(filepath.Ext(outputPath), ".txt") {
		outputPath += ".txt"
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", err
	}
	if err := storage.AtomicWriteText(outputPath, strings.Join(lines, "\n")+"\n"); err != nil {
		return "", err
	}
	return outputPath, nil
}

func extractConfigMakerConfigs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matches := configMakerURIRe.FindAllString(line, -1)
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			out = append(out, match)
		}
	}
	if len(out) > 0 {
		return out
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

func extractConfigMakerTargets(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	}) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		host, port, err := net.SplitHostPort(token)
		if err != nil || host == "" || port == "" {
			continue
		}
		if net.ParseIP(host) == nil {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func extractConfigMakerIPs(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := configMakerURIRe.FindString(line); match != "" {
			if endpoint := configMakerHostPort(match); endpoint != "" {
				if _, ok := seen[endpoint]; !ok {
					seen[endpoint] = struct{}{}
					out = append(out, endpoint)
				}
			}
		}
		for _, token := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
		}) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			host, port, err := net.SplitHostPort(token)
			if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

func configMakerHostPort(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := parsed.Host
	if strings.Contains(host, "@") {
		parts := strings.Split(host, "@")
		host = parts[len(parts)-1]
	}
	hn, port, err := net.SplitHostPort(host)
	if err != nil || hn == "" || port == "" || net.ParseIP(hn) == nil {
		return ""
	}
	return host
}

func rewriteConfigMakerConfigs(configs, targets []string) []string {
	if len(configs) == 0 || len(targets) == 0 {
		return nil
	}
	var out []string
	for i, cfg := range configs {
		target := targets[i%len(targets)]
		out = append(out, rewriteConfigMakerConfig(cfg, target))
	}
	return out
}

func rewriteConfigMakerConfig(configText, target string) string {
	configText = strings.TrimSpace(configText)
	if configText == "" || target == "" {
		return configText
	}
	if !strings.Contains(configText, "://") {
		return configText
	}
	parsed, err := url.Parse(configText)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return configText
	}
	userInfo := ""
	host := parsed.Host
	if strings.Contains(host, "@") {
		parts := strings.SplitN(host, "@", 2)
		userInfo = parts[0]
	}
	if userInfo != "" {
		parsed.Host = userInfo + "@" + target
	} else {
		parsed.Host = target
	}
	parsed.Fragment = target
	return parsed.String()
}

func previewStrings(items []string, max int) []string {
	if len(items) <= max {
		return append([]string(nil), items...)
	}
	return append([]string(nil), items[:max]...)
}
