package xudp

import (
	"strings"
)

// DNS wire format (RFC 1035):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Transaction ID                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |QR|  Opcode   |AA|TC|RD|RA| Z |   RCODE   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       QDCOUNT / ANCOUNT ...                   |
//
// Minimum DNS header is 12 bytes.
// QNAME starts at byte 12 as a sequence of length-prefixed labels,
// terminated by a zero-length label.
//
// We extract the query domain and use it as the routing key so that
// traffic for the same domain always routes to the same resolver backend.
// This is useful for split-horizon DNS where different domains should
// be handled by different upstream resolvers.

const dnsMinLen = 12

// dnsMatcher implements Matcher for DNS queries.
type dnsMatcher struct{}

func init() {
	registerMatcher(&dnsMatcher{})
}

func (d *dnsMatcher) Name() string { return "dns" }

// Match extracts the first query domain from a DNS question section.
// Returns ("", false) for responses (QR=1) and malformed packets.
func (d *dnsMatcher) Match(data []byte) (string, bool) {
	if len(data) < dnsMinLen {
		return "", false
	}

	// QR bit: bit 15 of flags (byte 2, bit 7).
	// 0 = query, 1 = response. We only route queries.
	if data[2]&0x80 != 0 {
		return "", false
	}

	// QDCOUNT: number of questions (bytes 4-5). Must be at least 1.
	qdcount := int(data[4])<<8 | int(data[5])
	if qdcount < 1 {
		return "", false
	}

	// Parse QNAME starting at byte 12.
	domain, ok := parseDNSName(data, 12)
	if !ok || domain == "" {
		return "", false
	}

	return strings.ToLower(domain), true
}

// parseDNSName reads a DNS name from data starting at offset.
// Returns the dotted domain string and whether parsing succeeded.
func parseDNSName(data []byte, offset int) (string, bool) {
	var labels []string
	visited := 0

	for {
		if offset >= len(data) {
			return "", false
		}

		length := int(data[offset])

		// Zero-length label = end of name
		if length == 0 {
			break
		}

		// Compression pointer: top two bits are 11
		if length&0xC0 == 0xC0 {
			// We don't follow pointers in query sections;
			// a well-formed question section won't have them.
			return "", false
		}

		// Label too long (RFC 1035: max 63 per label)
		if length > 63 {
			return "", false
		}

		offset++
		if offset+length > len(data) {
			return "", false
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length

		visited++
		if visited > 128 {
			// Malformed: too many labels
			return "", false
		}
	}

	if len(labels) == 0 {
		return "", false
	}

	return strings.Join(labels, "."), true
}

// IsDNSQuery returns true if data looks like a DNS query datagram.
// Exported for tests and health executor.
func IsDNSQuery(data []byte) bool {
	_, ok := (&dnsMatcher{}).Match(data)
	return ok
}
