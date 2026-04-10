package xudp

import (
	"testing"
)

// buildDNSQuery builds a minimal DNS query packet for the given domain.
// Format: 12-byte header + QNAME + QTYPE (A=1) + QCLASS (IN=1).
func buildDNSQuery(domain string) []byte {
	// Header: ID=0x1234, FLAGS=0x0100 (standard query, RD=1), QDCOUNT=1
	pkt := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: QR=0 (query), RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	// Encode QNAME as length-prefixed labels
	labels := splitDomain(domain)
	for _, label := range labels {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0x00) // root label

	// QTYPE = A (1), QCLASS = IN (1)
	pkt = append(pkt, 0x00, 0x01, 0x00, 0x01)

	return pkt
}

func splitDomain(domain string) []string {
	var labels []string
	cur := ""
	for _, c := range domain {
		if c == '.' {
			if cur != "" {
				labels = append(labels, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}

func TestDNSMatcher_SimpleQuery(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	m := &dnsMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected DNS match")
	}
	if key != "example.com" {
		t.Fatalf("expected %q, got %q", "example.com", key)
	}
}

func TestDNSMatcher_SubdomainQuery(t *testing.T) {
	pkt := buildDNSQuery("api.example.com")
	m := &dnsMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected DNS match for subdomain")
	}
	if key != "api.example.com" {
		t.Fatalf("expected %q, got %q", "api.example.com", key)
	}
}

func TestDNSMatcher_CaseNormalized(t *testing.T) {
	// DNS labels are case-insensitive; key should be lowercased
	pkt := buildDNSQuery("Example.COM")
	m := &dnsMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected DNS match")
	}
	if key != "example.com" {
		t.Fatalf("expected lowercase %q, got %q", "example.com", key)
	}
}

func TestDNSMatcher_ResponseIgnored(t *testing.T) {
	// QR=1 means response — should not match
	pkt := buildDNSQuery("example.com")
	pkt[2] |= 0x80 // set QR bit

	m := &dnsMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match for DNS response")
	}
}

func TestDNSMatcher_TooShort(t *testing.T) {
	m := &dnsMatcher{}
	_, ok := m.Match([]byte{0x12, 0x34, 0x01, 0x00})
	if ok {
		t.Fatal("expected no match for too-short packet")
	}
}

func TestDNSMatcher_ZeroQDCount(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	pkt[4] = 0x00
	pkt[5] = 0x00 // QDCOUNT = 0

	m := &dnsMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match when QDCOUNT is 0")
	}
}

func TestDNSMatcher_NonDNSPayload(t *testing.T) {
	m := &dnsMatcher{}
	_, ok := m.Match([]byte("this is not dns at all"))
	if ok {
		t.Fatal("expected no match for non-DNS payload")
	}
}

func TestDNSMatcher_TruncatedQNAME(t *testing.T) {
	// Header only, QNAME truncated mid-label
	pkt := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', // label "www" — truncated, no 'w' and no continuation
	}
	m := &dnsMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match for truncated QNAME")
	}
}

func TestDNSMatcher_Name(t *testing.T) {
	m := &dnsMatcher{}
	if m.Name() != "dns" {
		t.Fatalf("expected %q, got %q", "dns", m.Name())
	}
}

func TestDNSMatcher_RegisteredInRegistry(t *testing.T) {
	m := lookupMatcher("dns")
	if m == nil {
		t.Fatal("dns matcher not found in registry")
	}
}

func TestIsDNSQuery(t *testing.T) {
	valid := buildDNSQuery("test.example.com")
	if !IsDNSQuery(valid) {
		t.Fatal("IsDNSQuery should return true for valid DNS query")
	}
	if IsDNSQuery([]byte("not dns")) {
		t.Fatal("IsDNSQuery should return false for non-DNS data")
	}
}
