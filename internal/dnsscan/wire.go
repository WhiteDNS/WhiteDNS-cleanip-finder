// Package dnsscan is a self-contained DNS resolver scanner. It probes resolver
// IPs across UDP/TCP/DoT/DoH, decodes the full DNS response header, validates
// answer integrity against a trusted "truth table" (poisoning detection), and
// classifies which resolvers are suitable for DNS tunneling (open recursion +
// EDNS0 large-payload + TXT passthrough).
//
// It depends only on the Go standard library so it can be shared unchanged
// between the desktop TUI and the mobile bindings.
package dnsscan

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ednsUDPPayloadSize is the advertised EDNS0 receive-buffer size. 4096 lets a
// resolver return large answers in a single UDP datagram — both a robustness
// win (fewer truncations) and the signal we use to gauge tunnel bandwidth.
const ednsUDPPayloadSize = 4096

// DnsHeader is the fully-decoded 12-byte DNS message header (RFC 1035 §4.1.1).
type DnsHeader struct {
	ID      uint16 // Transaction ID
	QR      bool   // Query (false) / Response (true)
	Opcode  uint8  // 0=QUERY, 1=IQUERY, 2=STATUS
	AA      bool   // Authoritative Answer
	TC      bool   // TrunCation — answer did not fit, retry over TCP
	RD      bool   // Recursion Desired (what we asked for)
	RA      bool   // Recursion Available — resolver is an open recursor
	Z       uint8  // Reserved (3 bits)
	Rcode   uint8  // Response code (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED)
	QDCount uint16 // Questions
	ANCount uint16 // Answer records
	NSCount uint16 // Authority records
	ARCount uint16 // Additional records
}

// String renders the header as a compact single-line dump for reports.
func (h DnsHeader) String() string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("id=0x%04x qr=%d op=%d aa=%d tc=%d rd=%d ra=%d z=%d rcode=%d qd=%d an=%d ns=%d ar=%d",
		h.ID, b(h.QR), h.Opcode, b(h.AA), b(h.TC), b(h.RD), b(h.RA), h.Z, h.Rcode,
		h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}

// parseDnsHeader decodes the fixed 12-byte header at the start of a DNS message.
func parseDnsHeader(packet []byte) (DnsHeader, error) {
	if len(packet) < 12 {
		return DnsHeader{}, fmt.Errorf("packet too short for header: %d bytes", len(packet))
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return DnsHeader{
		ID:      binary.BigEndian.Uint16(packet[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		Rcode:   uint8(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(packet[4:6]),
		ANCount: binary.BigEndian.Uint16(packet[6:8]),
		NSCount: binary.BigEndian.Uint16(packet[8:10]),
		ARCount: binary.BigEndian.Uint16(packet[10:12]),
	}, nil
}

// buildDnsQuery constructs a raw DNS query for the given domain and record type.
// Returns the wire-format bytes and the randomized transaction ID. crypto/rand
// TXIDs both evade pattern-based DPI and let the caller validate that a response
// is genuinely ours (anti-spoofing). When edns is true an EDNS0 OPT record is
// appended so we can detect large-payload support.
func buildDnsQuery(domain string, qtype uint16, edns bool) ([]byte, uint16) {
	var txidBytes [2]byte
	_, _ = rand.Read(txidBytes[:])
	txid := binary.BigEndian.Uint16(txidBytes[:])

	arCount := byte(0x00)
	if edns {
		arCount = 0x01
	}

	header := []byte{
		txidBytes[0], txidBytes[1], // Transaction ID
		0x01, 0x00, // Flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, arCount, // ARCOUNT: 1 if EDNS OPT appended
	}

	question := encodeDomainName(domain)
	question = append(question, byte(qtype>>8), byte(qtype))
	question = append(question, 0x00, 0x01) // Class IN

	packet := append(header, question...)
	if edns {
		packet = append(packet, encodeEDNSOpt()...)
	}
	return packet, txid
}

// encodeEDNSOpt builds a minimal EDNS0 OPT pseudo-record (RFC 6891) for the
// additional section: root name, TYPE=OPT(41), CLASS=UDP payload size, zeroed
// extended-rcode/flags/version, empty RDATA.
func encodeEDNSOpt() []byte {
	return []byte{
		0x00,       // Root domain name
		0x00, 0x29, // TYPE: OPT (41)
		byte(ednsUDPPayloadSize >> 8), byte(ednsUDPPayloadSize & 0xFF), // CLASS: UDP payload size
		0x00,       // Extended RCODE
		0x00,       // EDNS version 0
		0x00, 0x00, // Z flags
		0x00, 0x00, // RDLENGTH: 0
	}
}

// encodeDomainName converts "google.com" into DNS wire format: [6]google[3]com[0]
func encodeDomainName(domain string) []byte {
	var buf []byte
	for _, part := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Root label terminator
	return buf
}

// skipDnsName advances past a DNS domain name, handling label sequences and
// pointer compression (0xC0 prefix). Returns -1 on malformed input.
func skipDnsName(packet []byte, offset int) int {
	for {
		if offset >= len(packet) {
			return -1
		}
		length := int(packet[offset])
		if length&0xC0 == 0xC0 {
			return offset + 2 // pointer is 2 bytes
		}
		if length == 0 {
			return offset + 1 // root label
		}
		offset += 1 + length
	}
}

// parseDnsMessage decodes a full DNS response: header, answer records of the
// requested type, and whether an EDNS0 OPT record is present anywhere. When
// checkTxid is set the response ID must equal wantTxid and QR must be set —
// rejecting blindly-spoofed / off-path injected packets.
func parseDnsMessage(packet []byte, qtype uint16, wantTxid uint16, checkTxid bool) (DnsHeader, []string, bool, error) {
	hdr, err := parseDnsHeader(packet)
	if err != nil {
		return DnsHeader{}, nil, false, err
	}
	if checkTxid && hdr.ID != wantTxid {
		return hdr, nil, false, fmt.Errorf("txid mismatch got=0x%04x want=0x%04x", hdr.ID, wantTxid)
	}
	if !hdr.QR {
		return hdr, nil, false, fmt.Errorf("not a response (QR=0)")
	}
	if hdr.Rcode != 0 {
		return hdr, nil, false, fmt.Errorf("dns error rcode=%d", hdr.Rcode)
	}

	offset := 12
	for i := 0; i < int(hdr.QDCount); i++ {
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+4 > len(packet) {
			return hdr, nil, false, fmt.Errorf("malformed question section")
		}
		offset += 4 // QTYPE + QCLASS
	}

	var answers []string
	edns := false
	total := int(hdr.ANCount) + int(hdr.NSCount) + int(hdr.ARCount)
	inAnswer := int(hdr.ANCount)

	for i := 0; i < total; i++ {
		if offset >= len(packet) {
			break
		}
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			break
		}
		rType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdLength := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
		offset += 2
		if offset+rdLength > len(packet) {
			break
		}
		if rType == 41 { // OPT => resolver understood our EDNS0 query
			edns = true
		}
		if i < inAnswer && rType == qtype {
			switch qtype {
			case 1:
				if rdLength == 4 {
					answers = append(answers, fmt.Sprintf("%d.%d.%d.%d",
						packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]))
				}
			case 16:
				if txt, err := parseTxtRData(packet[offset : offset+rdLength]); err == nil && txt != "" {
					answers = append(answers, txt)
				}
			}
		}
		offset += rdLength
	}

	if len(answers) == 0 {
		return hdr, nil, edns, fmt.Errorf("no %s records in response", dnsQueryTypeName(qtype))
	}
	return hdr, answers, edns, nil
}

func parseTxtRData(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("empty TXT record")
	}
	parts := make([]string, 0, 4)
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return "", fmt.Errorf("malformed TXT record")
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ""), nil
}

func dnsQueryTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 16:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE_%d", qtype)
	}
}

// dohJSONResponse models the JSON wire format returned by DoH providers queried
// with Accept: application/dns-json.
type dohJSONResponse struct {
	Status int  `json:"Status"`
	TC     bool `json:"TC"`
	RD     bool `json:"RD"`
	RA     bool `json:"RA"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dohHeader synthesizes a DnsHeader from the flags exposed by the DoH JSON API.
func dohHeader(r dohJSONResponse) DnsHeader {
	return DnsHeader{QR: true, TC: r.TC, RD: r.RD, RA: r.RA, Rcode: uint8(r.Status)}
}

// truncErr keeps error strings short for logs/reports.
func truncErr(err error) string {
	s := err.Error()
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

// isIP reports whether s parses as an IP literal.
func isIP(s string) bool { return net.ParseIP(strings.TrimSpace(s)) != nil }
