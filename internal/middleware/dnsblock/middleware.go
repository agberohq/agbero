package dnsblock

import "strings"

// Filter checks a raw DNS query wire-format datagram against bl.
// Returns (nxdomain_response, true) if the queried domain is blocked,
// or (nil, false) if the packet should be forwarded normally.
//
// Filter is safe for concurrent use; it acquires only a read lock on bl.
func Filter(query []byte, bl *Blocklist) ([]byte, bool) {
	domain, ok := extractQueryDomain(query)
	if !ok || domain == "" {
		return nil, false
	}

	if !bl.Match(domain) {
		return nil, false
	}

	resp, err := NXDOMAIN(query)
	if err != nil {
		// Malformed query — can't synthesise response; pass through.
		return nil, false
	}
	return resp, true
}

// extractQueryDomain parses the first QNAME from a DNS query datagram.
// It reuses the parsing logic from the xudp dnsMatcher but lives here so
// the dnsblock package is self-contained and testable without importing xudp.
//
// Returns ("", false) for responses (QR=1), malformed packets, or if no
// question section is present.
func extractQueryDomain(data []byte) (string, bool) {
	if len(data) < minDNSLen {
		return "", false
	}

	// QR bit (byte 2, bit 7): 0 = query, 1 = response.
	if data[2]&0x80 != 0 {
		return "", false
	}

	// QDCOUNT (bytes 4-5): must be at least 1.
	qdcount := int(data[4])<<8 | int(data[5])
	if qdcount < 1 {
		return "", false
	}

	// Parse QNAME starting at byte 12.
	domain, ok := parseDNSName(data, minDNSLen)
	if !ok || domain == "" {
		return "", false
	}
	return strings.ToLower(domain), true
}

// parseDNSName decodes a DNS wire-format name starting at offset in data.
// Returns the dotted-label string and true on success.
func parseDNSName(data []byte, offset int) (string, bool) {
	var labels []string
	visited := 0

	for {
		if offset >= len(data) {
			return "", false
		}

		length := int(data[offset])

		if length == 0 {
			break
		}

		// Compression pointer — not expected in query QNAME.
		if length&0xC0 == 0xC0 {
			return "", false
		}

		// RFC 1035: max 63 octets per label.
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
			return "", false
		}
	}

	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}
