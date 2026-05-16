package dnsblock

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olekukonko/ll"
)

// disabledLogger returns a silent logger for tests.
func disabledLogger() *ll.Logger { return ll.New("test").Disable() }

// NXDOMAIN

func TestNXDOMAIN_Basic(t *testing.T) {
	// Minimal valid DNS query: 12-byte header + question for "example.com" type A
	query := buildDNSQuery(0x1234, "example.com")

	resp, err := NXDOMAIN(query)
	if err != nil {
		t.Fatalf("NXDOMAIN() error: %v", err)
	}

	// Transaction ID must be mirrored
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Errorf("transaction ID: got %02x%02x, want %02x%02x",
			resp[0], resp[1], query[0], query[1])
	}

	// QR=1 (response)
	if resp[2]&0x80 == 0 {
		t.Error("QR bit must be set in NXDOMAIN response")
	}

	// RCODE=3 (NXDOMAIN)
	if resp[3]&0x0F != 3 {
		t.Errorf("RCODE: got %d, want 3 (NXDOMAIN)", resp[3]&0x0F)
	}

	// RA=1
	if resp[3]&0x80 == 0 {
		t.Error("RA bit must be set in NXDOMAIN response")
	}

	// Response must be same length as query (question section preserved)
	if len(resp) != len(query) {
		t.Errorf("len(resp)=%d, want %d", len(resp), len(query))
	}
}

func TestNXDOMAIN_PreservesTransactionID(t *testing.T) {
	for _, txid := range []uint16{0x0000, 0x0001, 0xFFFF, 0xABCD} {
		q := buildDNSQuery(txid, "test.com")
		resp, err := NXDOMAIN(q)
		if err != nil {
			t.Fatalf("NXDOMAIN(txid=%04x): %v", txid, err)
		}
		got := uint16(resp[0])<<8 | uint16(resp[1])
		if got != txid {
			t.Errorf("txid=%04x: response txid=%04x", txid, got)
		}
	}
}

func TestNXDOMAIN_TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 11} {
		_, err := NXDOMAIN(make([]byte, n))
		if err == nil {
			t.Errorf("NXDOMAIN(%d bytes): expected error, got nil", n)
		}
	}
}

func TestNXDOMAIN_PreservesQuestionSection(t *testing.T) {
	query := buildDNSQuery(0xBEEF, "blocked.ads.com")
	resp, _ := NXDOMAIN(query)

	// Bytes 12+ (question section) must be identical
	if !bytes.Equal(resp[12:], query[12:]) {
		t.Error("NXDOMAIN must preserve the question section verbatim")
	}
}

// Blocklist — Add / AddSlice / Len

func TestBlocklist_Add(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("ads.example.com")
	bl.Add("tracker.io")

	if bl.Len() != 2 {
		t.Errorf("Len() = %d, want 2", bl.Len())
	}
}

func TestBlocklist_Add_Normalises(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("  ADS.EXAMPLE.COM  ")
	if !bl.Match("ads.example.com") {
		t.Error("Add should normalise to lowercase and trim whitespace")
	}
}

func TestBlocklist_Add_Empty(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("")
	bl.Add("   ")
	if bl.Len() != 0 {
		t.Errorf("empty/whitespace Add should not increase Len, got %d", bl.Len())
	}
}

func TestBlocklist_AddSlice(t *testing.T) {
	bl := New(disabledLogger())
	bl.AddSlice([]string{"a.com", "b.com", "c.com"})
	if bl.Len() != 3 {
		t.Errorf("Len() = %d, want 3", bl.Len())
	}
}

func TestBlocklist_Wildcard(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("*.ads.example.com")

	if bl.SuffixLen() != 1 {
		t.Errorf("SuffixLen() = %d, want 1", bl.SuffixLen())
	}
	// Wildcard entry must not go into exact map
	if bl.Len() != 0 {
		t.Errorf("wildcard entry must not be in exact map, Len() = %d", bl.Len())
	}
}

// Blocklist — Match

func TestBlocklist_Match_ExactHit(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	if !bl.Match("blocked.com") {
		t.Error("exact match should return true")
	}
}

func TestBlocklist_Match_ExactMiss(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	if bl.Match("notblocked.com") {
		t.Error("non-blocked domain should return false")
	}
}

func TestBlocklist_Match_SubdomainNotBlocked(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("ads.example.com")

	// Exact entry does NOT block sub.ads.example.com — only wildcard does
	if bl.Match("sub.ads.example.com") {
		t.Error("exact entry should not block subdomain — use wildcard for that")
	}
}

func TestBlocklist_Match_WildcardSuffix(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("*.ads.example.com")

	cases := []struct {
		domain string
		want   bool
	}{
		{"sub.ads.example.com", true},
		{"deep.sub.ads.example.com", true},
		{"ads.example.com", true}, // exact match on suffix itself
		{"example.com", false},
		{"notads.example.com", false},
		{"ads.example.com.evil.com", false},
	}
	for _, c := range cases {
		got := bl.Match(c.domain)
		if got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestBlocklist_Match_CaseInsensitive(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("Blocked.COM")

	if !bl.Match("BLOCKED.COM") {
		t.Error("Match should be case-insensitive")
	}
	if !bl.Match("blocked.com") {
		t.Error("Match should be case-insensitive (lowercase)")
	}
}

func TestBlocklist_Match_EmptyDomain(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	if bl.Match("") {
		t.Error("empty domain should never match")
	}
}

func TestBlocklist_Match_EmptyBlocklist(t *testing.T) {
	bl := New(disabledLogger())
	if bl.Match("anything.com") {
		t.Error("empty blocklist should never match")
	}
}

// Blocklist — Load (reader)

func TestBlocklist_Load_BareDomain(t *testing.T) {
	bl := New(disabledLogger())
	r := strings.NewReader("ads.example.com\ntracker.io\n")
	if err := bl.Load(r); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bl.Match("ads.example.com") {
		t.Error("bare domain not loaded")
	}
	if !bl.Match("tracker.io") {
		t.Error("second domain not loaded")
	}
}

func TestBlocklist_Load_HostsFormat(t *testing.T) {
	bl := New(disabledLogger())
	input := `# This is a hosts file
0.0.0.0 ads.example.com
127.0.0.1 tracker.io
0.0.0.0 localhost
`
	if err := bl.Load(strings.NewReader(input)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bl.Match("ads.example.com") {
		t.Error("hosts-format entry not loaded")
	}
	if !bl.Match("tracker.io") {
		t.Error("127.0.0.1 hosts-format entry not loaded")
	}
	// localhost must be skipped
	if bl.Match("localhost") {
		t.Error("localhost must not be added to blocklist")
	}
}

func TestBlocklist_Load_CommentsAndBlanks(t *testing.T) {
	bl := New(disabledLogger())
	input := `
# comment
   
# another comment
ads.example.com # inline comment
`
	if err := bl.Load(strings.NewReader(input)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bl.Match("ads.example.com") {
		t.Error("domain with inline comment not loaded")
	}
	if bl.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (comments/blanks skipped)", bl.Len())
	}
}

func TestBlocklist_Load_IsAdditive(t *testing.T) {
	bl := New(disabledLogger())
	bl.Load(strings.NewReader("a.com\n"))
	bl.Load(strings.NewReader("b.com\n"))
	if bl.Len() != 2 {
		t.Errorf("Load should be additive, Len() = %d, want 2", bl.Len())
	}
}

// Blocklist — LoadFile

func TestBlocklist_LoadFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "blocklist.txt")
	os.WriteFile(f, []byte("ads.example.com\ntracker.io\n"), 0644)

	bl := New(disabledLogger())
	if err := bl.LoadFile(f); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !bl.Match("ads.example.com") {
		t.Error("domain from file not loaded")
	}
}

func TestBlocklist_LoadFile_NotFound(t *testing.T) {
	bl := New(disabledLogger())
	err := bl.LoadFile("/nonexistent/path/blocklist.txt")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// Blocklist — LoadURL (using httptest server)

func TestBlocklist_LoadURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.io\n"))
	}))
	defer srv.Close()

	bl := New(disabledLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := bl.LoadURL(ctx, srv.URL); err != nil {
		t.Fatalf("LoadURL: %v", err)
	}
	if !bl.Match("ads.example.com") {
		t.Error("domain from URL not loaded")
	}
}

func TestBlocklist_LoadURL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	bl := New(disabledLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := bl.LoadURL(ctx, srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
}

func TestBlocklist_LoadURL_StoresSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ads.example.com\n"))
	}))
	defer srv.Close()

	bl := New(disabledLogger())
	ctx := context.Background()
	bl.LoadURL(ctx, srv.URL)
	bl.LoadURL(ctx, srv.URL) // duplicate — must not add twice

	bl.mu.RLock()
	n := len(bl.urlSources)
	bl.mu.RUnlock()

	if n != 1 {
		t.Errorf("duplicate URL stored %d times, want 1", n)
	}
}

// Blocklist — Clear

func TestBlocklist_Clear(t *testing.T) {
	bl := New(disabledLogger())
	bl.AddSlice([]string{"a.com", "b.com"})
	bl.Add("*.wildcard.com")
	bl.Clear()

	if bl.Len() != 0 {
		t.Errorf("Len() after Clear = %d, want 0", bl.Len())
	}
	if bl.SuffixLen() != 0 {
		t.Errorf("SuffixLen() after Clear = %d, want 0", bl.SuffixLen())
	}
	if bl.Match("a.com") {
		t.Error("Clear should remove all entries")
	}
}

// Filter (middleware.go)

func TestFilter_BlockedDomain(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	query := buildDNSQuery(0x1234, "blocked.com")
	resp, ok := Filter(query, bl)

	if !ok {
		t.Fatal("Filter should return true for blocked domain")
	}
	if resp == nil {
		t.Fatal("Filter should return non-nil NXDOMAIN response")
	}
	// Verify it's actually an NXDOMAIN response
	if resp[3]&0x0F != 3 {
		t.Errorf("RCODE: got %d, want 3 (NXDOMAIN)", resp[3]&0x0F)
	}
}

func TestFilter_AllowedDomain(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	query := buildDNSQuery(0x5678, "allowed.com")
	resp, ok := Filter(query, bl)

	if ok {
		t.Error("Filter should return false for non-blocked domain")
	}
	if resp != nil {
		t.Error("Filter should return nil response for non-blocked domain")
	}
}

func TestFilter_DNSResponse_NotFiltered(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	// Build a DNS response (QR=1) — must pass through unfiltered
	query := buildDNSQuery(0x1234, "blocked.com")
	query[2] |= 0x80 // set QR=1 (response)

	_, ok := Filter(query, bl)
	if ok {
		t.Error("Filter must not block DNS responses (only queries)")
	}
}

func TestFilter_TooShort_NotFiltered(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	_, ok := Filter([]byte{0x00, 0x01}, bl)
	if ok {
		t.Error("Filter must not block malformed (too-short) packets")
	}
}

func TestFilter_EmptyBlocklist(t *testing.T) {
	bl := New(disabledLogger())
	query := buildDNSQuery(0xABCD, "anything.com")
	_, ok := Filter(query, bl)
	if ok {
		t.Error("empty blocklist must never block")
	}
}

func TestFilter_PreservesTransactionID(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("blocked.com")

	txid := uint16(0xDEAD)
	query := buildDNSQuery(txid, "blocked.com")
	resp, _ := Filter(query, bl)

	got := uint16(resp[0])<<8 | uint16(resp[1])
	if got != txid {
		t.Errorf("transaction ID: got %04x, want %04x", got, txid)
	}
}

func TestFilter_WildcardBlocked(t *testing.T) {
	bl := New(disabledLogger())
	bl.Add("*.ads.example.com")

	query := buildDNSQuery(0x0001, "sub.ads.example.com")
	_, ok := Filter(query, bl)
	if !ok {
		t.Error("wildcard suffix should block subdomain")
	}
}

// extractQueryDomain (middleware.go internal — tested indirectly via Filter
// but also directly since it's unexported)

func TestExtractQueryDomain_Valid(t *testing.T) {
	cases := []string{"example.com", "sub.domain.example.com", "a.b.c.d.e"}
	for _, domain := range cases {
		q := buildDNSQuery(0x0001, domain)
		got, ok := extractQueryDomain(q)
		if !ok {
			t.Errorf("extractQueryDomain(%q): ok=false", domain)
			continue
		}
		if got != strings.ToLower(domain) {
			t.Errorf("extractQueryDomain(%q) = %q, want %q", domain, got, strings.ToLower(domain))
		}
	}
}

func TestExtractQueryDomain_Response_Rejected(t *testing.T) {
	q := buildDNSQuery(0x0001, "example.com")
	q[2] |= 0x80 // QR=1 → response
	_, ok := extractQueryDomain(q)
	if ok {
		t.Error("DNS response must not be extracted as a query domain")
	}
}

func TestExtractQueryDomain_TooShort(t *testing.T) {
	_, ok := extractQueryDomain([]byte{0x00, 0x01, 0x02})
	if ok {
		t.Error("too-short packet must return ok=false")
	}
}

// Concurrency — race detector coverage

func TestBlocklist_ConcurrentReadWrite(t *testing.T) {
	bl := New(disabledLogger())
	done := make(chan struct{})

	// Writer
	go func() {
		for range 100 {
			bl.Add("ads.example.com")
		}
		close(done)
	}()

	// Readers
	for range 4 {
		go func() {
			for range 100 {
				bl.Match("ads.example.com")
			}
		}()
	}

	<-done
}

// DNS wire format builder (test helper)

// buildDNSQuery builds a minimal well-formed DNS query datagram for the given
// transaction ID and domain name, ready for use with Filter/NXDOMAIN tests.
func buildDNSQuery(txid uint16, domain string) []byte {
	buf := &bytes.Buffer{}

	// Transaction ID
	buf.WriteByte(byte(txid >> 8))
	buf.WriteByte(byte(txid))

	// Flags: QR=0 (query), RD=1
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// QNAME: encode each label
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // root label

	// QTYPE=A (1), QCLASS=IN (1)
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)

	return buf.Bytes()
}
