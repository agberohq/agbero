package xudp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/dnsblock"
	"github.com/olekukonko/ll"
)

// newTestProxy builds a started xudp.Proxy on a random UDP port.
func newTestProxy(t *testing.T) *Proxy {
	t.Helper()
	res := resource.New()
	res.Logger = ll.New("test").Disable()
	p := NewProxy(res, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("Proxy.Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p
}

// newTestProxyWithBackend builds a proxy with a real UDP echo backend and
// an optional blocklist.
func newTestProxyWithBackend(t *testing.T, bl *dnsblock.Blocklist) (*Proxy, string) {
	t.Helper()

	backendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { backendConn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := backendConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			backendConn.WriteToUDP(buf[:n], addr)
		}
	}()

	res := resource.New()
	res.Logger = ll.New("test").Disable()
	p := NewProxy(res, "127.0.0.1:0")
	if bl != nil {
		p.WithBlocklist(bl)
	}

	cfg := alaye.Proxy{
		Enabled:  expect.Active,
		Name:     "test",
		Listen:   "127.0.0.1:0",
		Protocol: "udp",
		Matcher:  "dns",
		Backends: []alaye.Server{alaye.NewServer(backendConn.LocalAddr().String())},
	}
	p.AddRoute("test", cfg)

	if err := p.Start(); err != nil {
		t.Fatalf("Proxy.Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p, backendConn.LocalAddr().String()
}

// sendDNSQuery sends a DNS query and returns the response.
func sendDNSQuery(t *testing.T, proxyAddr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return buf[:n]
}

// buildDNSQueryWithTXID wraps the existing buildDNSQuery (dns_test.go) and
// overwrites the transaction ID bytes, so tests can verify txid mirroring.
func buildDNSQueryWithTXID(txid uint16, domain string) []byte {
	q := buildDNSQuery(domain) // reuses dns_test.go helper (always txid=0x1234)
	q[0] = byte(txid >> 8)
	q[1] = byte(txid)
	return q
}

// isNXDOMAIN checks if a DNS response has RCODE=3.
func isNXDOMAIN(resp []byte) bool {
	return len(resp) >= 12 && resp[3]&0x0F == 3
}

// isResponse checks if the QR bit is set.
func isResponse(resp []byte) bool {
	return len(resp) >= 12 && resp[2]&0x80 != 0
}

// WithBlocklist — install/nil

func TestProxy_WithBlocklist_NilSafe(t *testing.T) {
	p := newTestProxy(t)
	p.WithBlocklist(nil) // must not panic
}

func TestProxy_WithBlocklist_Set(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	p := newTestProxy(t)
	p.WithBlocklist(bl)
	if p.blocklist == nil {
		t.Error("WithBlocklist should set p.blocklist")
	}
}

// Blocked domain — NXDOMAIN response returned to client

func TestProxy_BlockedDomain_NXDOMAIN(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	bl.Add("blocked.com")

	proxy, _ := newTestProxyWithBackend(t, bl)

	const txid = uint16(0xABCD)
	query := buildDNSQueryWithTXID(txid, "blocked.com")
	resp := sendDNSQuery(t, proxy.Listen, query)

	if !isResponse(resp) {
		t.Error("expected a DNS response (QR=1)")
	}
	if !isNXDOMAIN(resp) {
		t.Errorf("expected RCODE=3 (NXDOMAIN), got RCODE=%d", resp[3]&0x0F)
	}
	gotTXID := uint16(resp[0])<<8 | uint16(resp[1])
	if gotTXID != txid {
		t.Errorf("transaction ID: got %04x, want %04x", gotTXID, txid)
	}
}

// Allowed domain — forwarded to backend (echoed back)

func TestProxy_AllowedDomain_Forwarded(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	bl.Add("blocked.com")

	proxy, _ := newTestProxyWithBackend(t, bl)

	query := buildDNSQuery("allowed.com")
	resp := sendDNSQuery(t, proxy.Listen, query)

	if isNXDOMAIN(resp) {
		t.Error("allowed domain should not receive NXDOMAIN")
	}
	if !bytes.Equal(resp, query) {
		t.Error("echo backend should return query verbatim")
	}
}

// No blocklist — traffic passes through normally

func TestProxy_NoBlocklist_PassThrough(t *testing.T) {
	proxy, _ := newTestProxyWithBackend(t, nil)

	query := buildDNSQuery("example.com")
	resp := sendDNSQuery(t, proxy.Listen, query)

	if isNXDOMAIN(resp) {
		t.Error("without blocklist, all domains should pass through")
	}
	if !bytes.Equal(resp, query) {
		t.Error("echo backend should return query verbatim")
	}
}

// Wildcard blocking

func TestProxy_WildcardDomain_Blocked(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	bl.Add("*.ads.example.com")

	proxy, _ := newTestProxyWithBackend(t, bl)

	resp := sendDNSQuery(t, proxy.Listen, buildDNSQuery("sub.ads.example.com"))
	if !isNXDOMAIN(resp) {
		t.Error("wildcard-blocked subdomain should receive NXDOMAIN")
	}
}

func TestProxy_WildcardDomain_ParentNotBlocked(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	bl.Add("*.ads.example.com")

	proxy, _ := newTestProxyWithBackend(t, bl)

	resp := sendDNSQuery(t, proxy.Listen, buildDNSQuery("example.com"))
	if isNXDOMAIN(resp) {
		t.Error("parent domain should not be blocked by wildcard entry")
	}
}

// Multiple domains — independent block decisions

func TestProxy_MixedDomains(t *testing.T) {
	bl := dnsblock.New(ll.New("test").Disable())
	bl.AddSlice([]string{"ads.com", "tracker.io", "malware.net"})

	proxy, _ := newTestProxyWithBackend(t, bl)

	for _, domain := range []string{"ads.com", "tracker.io", "malware.net"} {
		resp := sendDNSQuery(t, proxy.Listen, buildDNSQuery(domain))
		if !isNXDOMAIN(resp) {
			t.Errorf("domain %q should be blocked", domain)
		}
	}
	for _, domain := range []string{"allowed.com", "safe.org", "example.net"} {
		resp := sendDNSQuery(t, proxy.Listen, buildDNSQuery(domain))
		if isNXDOMAIN(resp) {
			t.Errorf("domain %q should not be blocked", domain)
		}
	}
}

func TestDNSBlock_Validate_Valid(t *testing.T) {
	cases := []alaye.DNSBlock{
		{Enabled: expect.Inactive},
		{Enabled: expect.Active, Mode: "nxdomain"},
		{Enabled: expect.Active, Mode: "drop"},
		{Enabled: expect.Active, Mode: "", Domains: []string{"ads.com"}},
	}
	for i, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("case[%d]: Validate() unexpected error: %v", i, err)
		}
	}
}

func TestDNSBlock_Validate_InvalidMode(t *testing.T) {
	d := alaye.DNSBlock{Enabled: expect.Active, Mode: "refuse"}
	if err := d.Validate(); err == nil {
		t.Error("expected error for unsupported mode, got nil")
	}
}

func TestDNSBlock_Validate_NegativeRefresh(t *testing.T) {
	d := alaye.DNSBlock{Enabled: expect.Active, Refresh: -1}
	if err := d.Validate(); err == nil {
		t.Error("expected error for negative refresh, got nil")
	}
}

func TestDNSBlock_Validate_Disabled_SkipsAll(t *testing.T) {
	d := alaye.DNSBlock{Enabled: expect.Inactive, Mode: "refuse", Refresh: -1}
	if err := d.Validate(); err != nil {
		t.Errorf("disabled DNSBlock should skip validation, got: %v", err)
	}
}

func TestDNSBlock_IsZero(t *testing.T) {
	zero := alaye.DNSBlock{}
	if !zero.IsZero() {
		t.Error("empty DNSBlock.IsZero() should return true")
	}
	nonZero := alaye.DNSBlock{Mode: "nxdomain"}
	if nonZero.IsZero() {
		t.Error("DNSBlock with Mode set IsZero() should return false")
	}
}

func TestProxy_Validate_DNSBlock_InvalidMode(t *testing.T) {
	p := alaye.Proxy{
		Enabled:  expect.Active,
		Name:     "dns",
		Listen:   "127.0.0.1:5353",
		Protocol: "udp",
		Backends: []alaye.Server{alaye.NewServer("1.1.1.1:53")},
		DNSBlock: alaye.DNSBlock{Enabled: expect.Active, Mode: "bad-mode"},
	}
	if err := p.Validate(); err == nil {
		t.Error("Proxy.Validate() should propagate DNSBlock validation error")
	}
}

func TestProxy_Validate_DNSBlock_Valid(t *testing.T) {
	p := alaye.Proxy{
		Enabled:  expect.Active,
		Name:     "dns",
		Listen:   "127.0.0.1:5353",
		Protocol: "udp",
		Backends: []alaye.Server{alaye.NewServer("1.1.1.1:53")},
		DNSBlock: alaye.DNSBlock{
			Enabled: expect.Active,
			Mode:    "nxdomain",
			Domains: []string{"ads.example.com"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Proxy.Validate() unexpected error: %v", err)
	}
}
