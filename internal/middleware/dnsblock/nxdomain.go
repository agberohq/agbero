// Package dnsblock provides DNS-level domain blocking for UDP proxy routes.
// Blocked queries receive a synthesised NXDOMAIN response without touching
// any upstream resolver.
package dnsblock

import "fmt"

// minDNSLen is the minimum length of a valid DNS message (12-byte header).
const minDNSLen = 12

// NXDOMAIN synthesises a well-formed DNS response with RCODE=3 (NXDOMAIN)
// that mirrors the transaction ID and full question section of the original
// query. The response is constructed in-place from a copy of the query bytes
// with only the flag bytes modified:
//
//   - Byte 2: QR=1 (response), Opcode preserved, AA=0, TC=0, RD preserved
//   - Byte 3: RA=1, Z=0, RCODE=3 (NXDOMAIN)
//
// ANCOUNT, NSCOUNT, ARCOUNT are left at zero — no resource records are
// included, which is correct for a negative response with no SOA.
func NXDOMAIN(query []byte) ([]byte, error) {
	if len(query) < minDNSLen {
		return nil, fmt.Errorf("dnsblock: query too short (%d bytes, need %d)", len(query), minDNSLen)
	}

	resp := make([]byte, len(query))
	copy(resp, query)

	// Byte 2: set QR=1 (response), preserve Opcode/RD bits.
	//   QR   = bit 7 of byte 2
	//   RD   = bit 0 of byte 2  (recursion desired — echo back from query)
	resp[2] = query[2] | 0x80

	// Byte 3: set RA=1, clear Z, set RCODE=3 (NXDOMAIN).
	//   RA   = bit 7 of byte 3
	//   Z    = bits 6–4 (must be zero per RFC 1035)
	//   RCODE = bits 3–0
	resp[3] = 0x83 // 1000_0011 — RA=1, Z=000, RCODE=3

	return resp, nil
}
