package dnsscan

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReportPaths lists the files written by WriteReports.
type ReportPaths struct {
	Dir         string
	Full        string // human-readable per-resolver + header dump
	TunnelReady string // tunnel-ready shortlist
	Passed      string // plain IP list of clean (valid) resolvers, one per line
	CSV         string
	HTML        string // colour-coded per-status table (opens in browser/Excel)
	XLSX        string // real spreadsheet with per-status cell fills
	JSON        string
}

// statusCounts tallies how many resolvers landed in each state.
func statusCounts(results []ResolverResult) map[string]int {
	c := map[string]int{}
	for _, r := range results {
		c[r.Status]++
	}
	return c
}

// WriteReports dumps every result to dir in txt, csv, and json (range-scout
// parity: txt/csv/json export). Files are timestamped. dir is created if needed.
func WriteReports(dir string, results []ResolverResult) (ReportPaths, error) {
	var paths ReportPaths
	if strings.TrimSpace(dir) == "" {
		dir = "dns scan"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return paths, err
	}
	ts := time.Now().Format("20060102_150405")
	paths.Dir = dir

	sorted := append([]ResolverResult(nil), results...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score // best first
		}
		return sorted[i].IP < sorted[j].IP
	})

	paths.Full = filepath.Join(dir, fmt.Sprintf("dns_scan_%s.txt", ts))
	if err := writeFullReport(paths.Full, sorted); err != nil {
		return paths, err
	}
	paths.TunnelReady = filepath.Join(dir, fmt.Sprintf("tunnel_ready_%s.txt", ts))
	if err := writeTunnelReport(paths.TunnelReady, sorted); err != nil {
		return paths, err
	}
	paths.Passed = filepath.Join(dir, fmt.Sprintf("passed_clean_resolvers_%s.txt", ts))
	if err := writePassedList(paths.Passed, sorted); err != nil {
		return paths, err
	}
	paths.CSV = filepath.Join(dir, fmt.Sprintf("resolvers_%s.csv", ts))
	if err := writeCSV(paths.CSV, sorted); err != nil {
		return paths, err
	}
	paths.HTML = filepath.Join(dir, fmt.Sprintf("resolvers_%s.html", ts))
	if err := writeHTML(paths.HTML, sorted); err != nil {
		return paths, err
	}
	paths.XLSX = filepath.Join(dir, fmt.Sprintf("resolvers_%s.xlsx", ts))
	if err := writeXLSX(paths.XLSX, sorted); err != nil {
		return paths, err
	}
	paths.JSON = filepath.Join(dir, fmt.Sprintf("resolvers_%s.json", ts))
	if err := writeJSON(paths.JSON, sorted); err != nil {
		return paths, err
	}
	return paths, nil
}

func writeFullReport(path string, results []ResolverResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS Resolver / Tunnel Scan\nGenerated: %s\nTotal: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(results))
	c := statusCounts(results)
	fmt.Fprintf(&b, "States: valid(green)=%d  poison(purple)=%d  hijack(yellow)=%d  invalid(red)=%d\n",
		c[StatusValid], c[StatusPoison], c[StatusHijack], c[StatusInvalid])
	b.WriteString("Score 0-6 = UDP + TCP + RA + EDNS0 + TXT-passthrough + answer-integrity\n")
	b.WriteString("Header fields per probe: qr/aa/tc/rd/ra flags, rcode, and qd/an/ns/ar section counts.\n")
	b.WriteString(strings.Repeat("=", 90) + "\n")
	for _, r := range results {
		fmt.Fprintf(&b, "\n%-21s [%s] score=%d/6 tunnel=%s poison=%v hijack=%v %dms\n",
			r.IP, strings.ToUpper(r.Status), r.Score, ynb(r.TunnelReady), r.Poisoned, r.Transparent, r.BestLatency.Milliseconds())
		fmt.Fprintf(&b, "    RA=%v EDNS0=%v TXT-pass=%v UDP=%v TCP=%v NS-records=%d AR-records=%d reason=%s\n",
			r.RA, r.EDNS, r.TxtPass, r.UDPOK, r.TCPOK, r.NSCount, r.ARCount, r.TunnelReason)
		if r.PoisonIP != "" {
			fmt.Fprintf(&b, "    POISON: %s answered with off-truth IP(s) -> %s\n", r.IP, r.PoisonIP)
		}
		if r.HijackIP != "" {
			fmt.Fprintf(&b, "    HIJACK forged A for nonexistent name -> %s\n", r.HijackIP)
		}
		for _, hd := range r.HeaderDump() {
			b.WriteString("    " + hd + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeTunnelReport(path string, results []ResolverResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Tunnel-Ready DNS Resolvers\nGenerated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	b.WriteString("Criteria: open recursion (RA) + EDNS0 large-payload + TXT passthrough\n")
	b.WriteString(strings.Repeat("=", 70) + "\n")
	count := 0
	for _, r := range results {
		if !r.TunnelReady {
			continue
		}
		count++
		fmt.Fprintf(&b, "%-21s score=%d/6 poison=%v transparent=%v %dms\n",
			r.IP, r.Score, r.Poisoned, r.Transparent, r.BestLatency.Milliseconds())
	}
	fmt.Fprintf(&b, "\nTotal tunnel-ready: %d\n", count)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// writePassedList dumps just the IPs of clean (valid) resolvers — one per line,
// no headers or extra text — so the passed list can be pasted straight into a
// client/config. "Clean" = responded honestly (not poison / hijack / invalid).
func writePassedList(path string, results []ResolverResult) error {
	var b strings.Builder
	for _, r := range results {
		if r.Status == StatusValid {
			b.WriteString(r.IP + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeCSV(path string, results []ResolverResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	// status + color make the per-state verdict explicit so spreadsheets can
	// conditional-format it (poison=purple, hijack=yellow, valid=green,
	// invalid=red); resolvers_*.html renders those colours directly.
	_ = w.Write([]string{"ip", "status", "color", "score", "responded", "udp", "tcp", "ra", "edns", "txt_pass", "ns_records", "ar_records", "poisoned", "poison_ip", "hijacked", "hijack_ip", "tunnel_ready", "latency_ms", "nearby", "reason"})
	for _, r := range results {
		_ = w.Write([]string{
			r.IP,
			r.Status,
			StatusColor(r.Status),
			strconv.Itoa(r.Score),
			strconv.FormatBool(r.Responded),
			strconv.FormatBool(r.UDPOK),
			strconv.FormatBool(r.TCPOK),
			strconv.FormatBool(r.RA),
			strconv.FormatBool(r.EDNS),
			strconv.FormatBool(r.TxtPass),
			strconv.Itoa(r.NSCount),
			strconv.Itoa(r.ARCount),
			strconv.FormatBool(r.Poisoned),
			r.PoisonIP,
			strconv.FormatBool(r.Transparent),
			r.HijackIP,
			strconv.FormatBool(r.TunnelReady),
			strconv.FormatInt(r.BestLatency.Milliseconds(), 10),
			strconv.FormatBool(r.Nearby),
			r.TunnelReason,
		})
	}
	return w.Error()
}

// htmlStatusFill maps a status to a spreadsheet/browser-friendly row fill.
var htmlStatusFill = map[string]string{
	StatusPoison:  "#b39ddb", // purple
	StatusHijack:  "#fff59d", // yellow
	StatusValid:   "#a5d6a7", // green
	StatusInvalid: "#ef9a9a", // red
}

// writeHTML renders a colour-coded table where every row is filled by resolver
// status (poison=purple, hijack=yellow, valid=green, invalid=red). It opens in
// any browser and imports into Excel/LibreOffice with the fills preserved, so
// the colours requested for the CSV are actually visible. Columns surface the
// EDNS0, TXT-passthrough, and NS/AR header data probed per resolver.
func writeHTML(path string, results []ResolverResult) error {
	c := statusCounts(results)
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=\"utf-8\"><title>DNS Resolver Scan</title>\n")
	b.WriteString("<style>body{font:13px system-ui,Segoe UI,Arial,sans-serif;margin:16px}" +
		"table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:3px 7px;text-align:left;white-space:nowrap}" +
		"th{background:#333;color:#fff;position:sticky;top:0}code{font:12px Consolas,monospace}" +
		".legend span{display:inline-block;padding:2px 8px;margin-right:8px;border:1px solid #999}</style>\n")
	fmt.Fprintf(&b, "<h2>DNS Resolver / Tunnel Scan</h2><p>Generated: %s &middot; Total: %d</p>\n",
		html.EscapeString(time.Now().Format("2006-01-02 15:04:05")), len(results))
	fmt.Fprintf(&b, "<p class=legend>"+
		"<span style=\"background:%s\">valid: %d</span>"+
		"<span style=\"background:%s\">poison: %d</span>"+
		"<span style=\"background:%s\">hijack: %d</span>"+
		"<span style=\"background:%s\">invalid: %d</span></p>\n",
		htmlStatusFill[StatusValid], c[StatusValid], htmlStatusFill[StatusPoison], c[StatusPoison],
		htmlStatusFill[StatusHijack], c[StatusHijack], htmlStatusFill[StatusInvalid], c[StatusInvalid])
	b.WriteString("<table><tr><th>IP</th><th>Status</th><th>Score</th><th>RA</th><th>EDNS0</th>" +
		"<th>TXT-pass</th><th>UDP</th><th>TCP</th><th>NS</th><th>AR</th><th>Poison</th><th>Poison IP</th>" +
		"<th>Hijack</th><th>Hijack IP</th><th>Tunnel</th><th>ms</th><th>Reason</th>" +
		"<th>Headers (qr/aa/tc/rd/ra rcode qd/an/ns/ar)</th></tr>\n")
	esc := html.EscapeString
	for _, r := range results {
		fill := htmlStatusFill[r.Status]
		if fill == "" {
			fill = htmlStatusFill[StatusInvalid]
		}
		fmt.Fprintf(&b, "<tr style=\"background:%s\"><td><code>%s</code></td><td><b>%s</b></td>"+
			"<td>%d/6</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td>"+
			"<td>%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>\n",
			fill, esc(r.IP), esc(strings.ToUpper(r.Status)), r.Score,
			ynb(r.RA), ynb(r.EDNS), ynb(r.TxtPass), ynb(r.UDPOK), ynb(r.TCPOK), r.NSCount, r.ARCount,
			ynb(r.Poisoned), esc(r.PoisonIP), ynb(r.Transparent), esc(r.HijackIP),
			ynb(r.TunnelReady), r.BestLatency.Milliseconds(),
			esc(r.TunnelReason), esc(strings.Join(r.HeaderDump(), " ⏐ ")))
	}
	b.WriteString("</table>\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// jsonResolver is the export view (flattened, no raw probe internals).
type jsonResolver struct {
	IP          string   `json:"ip"`
	Status      string   `json:"status"`
	Color       string   `json:"color"`
	Score       int      `json:"score"`
	Responded   bool     `json:"responded"`
	UDP         bool     `json:"udp"`
	TCP         bool     `json:"tcp"`
	RA          bool     `json:"recursion_available"`
	EDNS        bool     `json:"edns0"`
	TxtPass     bool     `json:"txt_passthrough"`
	NSCount     int      `json:"ns_records"`
	ARCount     int      `json:"ar_records"`
	Poisoned    bool     `json:"poisoned"`
	PoisonIP    string   `json:"poison_ip,omitempty"`
	HijackIP    string   `json:"hijack_ip,omitempty"`
	Transparent bool     `json:"transparent_proxy"`
	TunnelReady bool     `json:"tunnel_ready"`
	LatencyMs   int64    `json:"latency_ms"`
	Nearby      bool     `json:"nearby"`
	Reason      string   `json:"reason"`
	Headers     []string `json:"headers"`
}

func writeJSON(path string, results []ResolverResult) error {
	out := make([]jsonResolver, 0, len(results))
	for _, r := range results {
		out = append(out, jsonResolver{
			IP: r.IP, Status: r.Status, Color: StatusColor(r.Status), Score: r.Score,
			Responded: r.Responded, UDP: r.UDPOK, TCP: r.TCPOK,
			RA: r.RA, EDNS: r.EDNS, TxtPass: r.TxtPass, NSCount: r.NSCount, ARCount: r.ARCount,
			Poisoned: r.Poisoned, PoisonIP: r.PoisonIP, HijackIP: r.HijackIP,
			Transparent: r.Transparent, TunnelReady: r.TunnelReady,
			LatencyMs: r.BestLatency.Milliseconds(), Nearby: r.Nearby, Reason: r.TunnelReason,
			Headers: r.HeaderDump(),
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ynb(v bool) string {
	if v {
		return "Y"
	}
	return "N"
}

// ── Colour-filled XLSX report ────────────────────────────────────────────────
//
// CSV has no concept of cell colour, so to deliver a genuinely colour-coded
// spreadsheet we emit a minimal (stdlib-only) OOXML .xlsx whose rows are filled
// by resolver status: poison=purple, hijack=yellow, valid=green, invalid=red.
// It opens in Excel/LibreOffice/Google Sheets with the fills intact.

// xlsxStatusStyle maps a status to its two cellXfs style indices (left-aligned
// for text columns, centre-aligned for flag/number columns) defined in
// xlsxStyles. Both carry the status fill colour.
func xlsxStatusStyle(status string) (left, center int) {
	switch status {
	case StatusValid:
		return 2, 3 // green
	case StatusPoison:
		return 4, 5 // purple
	case StatusHijack:
		return 6, 7 // yellow
	default:
		return 8, 9 // red (invalid)
	}
}

func xlsxCol(i int) string { return string(rune('A' + i)) }

func xlsxStr(b *bytes.Buffer, col int, row, style int, val string) {
	fmt.Fprintf(b, `<c r="%s%d" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`,
		xlsxCol(col), row, style, html.EscapeString(val))
}

func xlsxNum(b *bytes.Buffer, col int, row, style int, n int64) {
	fmt.Fprintf(b, `<c r="%s%d" s="%d"><v>%d</v></c>`, xlsxCol(col), row, style, n)
}

func writeXLSX(path string, results []ResolverResult) error {
	headers := []string{"IP", "Status", "Score", "RA", "EDNS0", "TXT-pass", "UDP", "TCP",
		"NS", "AR", "Poison", "Poison IP", "Hijack", "Hijack IP", "Tunnel", "ms", "Reason"}

	lastRow := len(results) + 1
	sheetRange := fmt.Sprintf("A1:%s%d", xlsxCol(len(headers)-1), lastRow)

	var sheet bytes.Buffer
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sheet.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	fmt.Fprintf(&sheet, `<dimension ref="%s"/>`, sheetRange)
	// Freeze the header row so it stays visible while scrolling.
	sheet.WriteString(`<sheetViews><sheetView tabSelected="1" workbookViewId="0">` +
		`<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>` +
		`<selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>`)
	sheet.WriteString(`<sheetFormatPr defaultRowHeight="15"/>`)
	sheet.WriteString(xlsxCols)

	sheet.WriteString(`<sheetData>`)
	sheet.WriteString(`<row r="1" ht="18" customHeight="1">`)
	for c, h := range headers {
		xlsxStr(&sheet, c, 1, 1, h) // header style
	}
	sheet.WriteString(`</row>`)
	// Columns that hold free text / addresses read best left-aligned; the compact
	// flag and number columns read best centred.
	leftCols := map[int]bool{0: true, 1: true, 11: true, 13: true, 16: true}
	for i, r := range results {
		row := i + 2
		left, center := xlsxStatusStyle(r.Status)
		st := func(col int) int {
			if leftCols[col] {
				return left
			}
			return center
		}
		fmt.Fprintf(&sheet, `<row r="%d">`, row)
		xlsxStr(&sheet, 0, row, st(0), r.IP)
		xlsxStr(&sheet, 1, row, st(1), strings.ToUpper(r.Status))
		xlsxNum(&sheet, 2, row, st(2), int64(r.Score))
		xlsxStr(&sheet, 3, row, st(3), ynb(r.RA))
		xlsxStr(&sheet, 4, row, st(4), ynb(r.EDNS))
		xlsxStr(&sheet, 5, row, st(5), ynb(r.TxtPass))
		xlsxStr(&sheet, 6, row, st(6), ynb(r.UDPOK))
		xlsxStr(&sheet, 7, row, st(7), ynb(r.TCPOK))
		xlsxNum(&sheet, 8, row, st(8), int64(r.NSCount))
		xlsxNum(&sheet, 9, row, st(9), int64(r.ARCount))
		xlsxStr(&sheet, 10, row, st(10), ynb(r.Poisoned))
		xlsxStr(&sheet, 11, row, st(11), r.PoisonIP)
		xlsxStr(&sheet, 12, row, st(12), ynb(r.Transparent))
		xlsxStr(&sheet, 13, row, st(13), r.HijackIP)
		xlsxStr(&sheet, 14, row, st(14), ynb(r.TunnelReady))
		xlsxNum(&sheet, 15, row, st(15), r.BestLatency.Milliseconds())
		xlsxStr(&sheet, 16, row, st(16), r.TunnelReason)
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData>`)
	fmt.Fprintf(&sheet, `<autoFilter ref="%s"/>`, sheetRange)
	sheet.WriteString(`</worksheet>`)

	parts := []struct{ name, body string }{
		{"[Content_Types].xml", xlsxContentTypes},
		{"_rels/.rels", xlsxRootRels},
		{"xl/workbook.xml", xlsxWorkbook},
		{"xl/_rels/workbook.xml.rels", xlsxWorkbookRels},
		{"xl/styles.xml", xlsxStyles},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

const xlsxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
	`</Types>`

const xlsxRootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const xlsxWorkbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
	`<sheets><sheet name="Resolvers" sheetId="1" r:id="rId1"/></sheets></workbook>`

const xlsxWorkbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`</Relationships>`

// xlsxCols sets sensible column widths so IPs, block-page addresses, and the
// reason text are fully visible without manual resizing.
const xlsxCols = `<cols>` +
	`<col min="1" max="1" width="18" customWidth="1"/>` + // IP
	`<col min="2" max="2" width="10" customWidth="1"/>` + // Status
	`<col min="3" max="3" width="7" customWidth="1"/>` + // Score
	`<col min="4" max="5" width="8" customWidth="1"/>` + // RA, EDNS0
	`<col min="6" max="6" width="10" customWidth="1"/>` + // TXT-pass
	`<col min="7" max="8" width="6" customWidth="1"/>` + // UDP, TCP
	`<col min="9" max="10" width="5" customWidth="1"/>` + // NS, AR
	`<col min="11" max="11" width="8" customWidth="1"/>` + // Poison
	`<col min="12" max="12" width="22" customWidth="1"/>` + // Poison IP
	`<col min="13" max="13" width="8" customWidth="1"/>` + // Hijack
	`<col min="14" max="14" width="22" customWidth="1"/>` + // Hijack IP
	`<col min="15" max="15" width="8" customWidth="1"/>` + // Tunnel
	`<col min="16" max="16" width="7" customWidth="1"/>` + // ms
	`<col min="17" max="17" width="46" customWidth="1"/>` + // Reason
	`</cols>`

// xlsxStyles defines fonts, the four status fills + header fill, and the cellXfs
// referenced by cells: 0 default, 1 header (bold/centred), then per status a
// left-aligned and a centre-aligned variant — green 2/3, purple 4/5, yellow 6/7,
// red 8/9.
const xlsxStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
	`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>` +
	`<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts>` +
	`<fills count="7">` +
	`<fill><patternFill patternType="none"/></fill>` +
	`<fill><patternFill patternType="gray125"/></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FF333333"/></patternFill></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FFA5D6A7"/></patternFill></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FFB39DDB"/></patternFill></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FFFFF59D"/></patternFill></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FFEF9A9A"/></patternFill></fill>` +
	`</fills>` +
	`<borders count="1"><border/></borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="10">` +
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	`<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="left" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="left" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="left" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="left" vertical="center"/></xf>` +
	`<xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>` +
	`</cellXfs></styleSheet>`
