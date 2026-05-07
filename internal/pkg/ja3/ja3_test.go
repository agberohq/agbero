package ja3

import (
	"crypto/tls"
	"strings"
	"testing"
)

// filterAndJoin16 / joinUint8s

func TestFilterAndJoin16_FiltersGREASE(t *testing.T) {
	// GREASE values must be stripped
	input := []uint16{0x0a0a, 0x002f, 0xfafa, 0x0035}
	got := filterAndJoin16(input)
	if strings.Contains(got, "2570") { // 0x0a0a
		t.Errorf("filterAndJoin16 leaked GREASE value 0x0a0a in %q", got)
	}
	if strings.Contains(got, "64250") { // 0xfafa
		t.Errorf("filterAndJoin16 leaked GREASE value 0xfafa in %q", got)
	}
	// Non-GREASE values must be present
	if !strings.Contains(got, "47") { // 0x002f
		t.Errorf("filterAndJoin16 dropped non-GREASE value 47 from %q", got)
	}
	if !strings.Contains(got, "53") { // 0x0035
		t.Errorf("filterAndJoin16 dropped non-GREASE value 53 from %q", got)
	}
}

func TestFilterAndJoin16_Empty(t *testing.T) {
	got := filterAndJoin16(nil)
	if got != "" {
		t.Errorf("filterAndJoin16(nil) = %q, want \"\"", got)
	}
}

func TestFilterAndJoin16_AllGREASE(t *testing.T) {
	got := filterAndJoin16([]uint16{0x0a0a, 0x1a1a, 0xfafa})
	if got != "" {
		t.Errorf("filterAndJoin16 all-GREASE = %q, want \"\"", got)
	}
}

func TestFilterAndJoin16_SingleValue(t *testing.T) {
	got := filterAndJoin16([]uint16{0x002f})
	if got != "47" {
		t.Errorf("filterAndJoin16([0x002f]) = %q, want \"47\"", got)
	}
}

func TestFilterAndJoin16_MultipleValues(t *testing.T) {
	got := filterAndJoin16([]uint16{0x002f, 0x0035, 0xc02b})
	// Must be dash-separated
	parts := strings.Split(got, "-")
	if len(parts) != 3 {
		t.Errorf("filterAndJoin16: expected 3 parts, got %d in %q", len(parts), got)
	}
}

func TestJoinUint8s(t *testing.T) {
	got := joinUint8s([]uint8{0, 1, 4})
	if got != "0-1-4" {
		t.Errorf("joinUint8s([0,1,4]) = %q, want \"0-1-4\"", got)
	}
}

func TestJoinUint8s_Empty(t *testing.T) {
	got := joinUint8s(nil)
	if got != "" {
		t.Errorf("joinUint8s(nil) = %q, want \"\"", got)
	}
}

// Raw / Compute — nil safety

func TestRaw_NilHello(t *testing.T) {
	got := Raw(nil)
	if got != "" {
		t.Errorf("Raw(nil) = %q, want \"\"", got)
	}
}

func TestCompute_NilHello(t *testing.T) {
	got := Compute(nil)
	if got != "" {
		t.Errorf("Compute(nil) = %q, want \"\"", got)
	}
}

// Raw — structure validation

func TestRaw_Format(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02b, 0xc02c},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
	}

	raw := Raw(hello)

	// Must have exactly 4 commas (5 fields)
	commas := strings.Count(raw, ",")
	if commas != 4 {
		t.Errorf("Raw: expected 4 commas (5 fields), got %d in %q", commas, raw)
	}

	// First field must be a decimal version number
	parts := strings.SplitN(raw, ",", 5)
	if len(parts) != 5 {
		t.Fatalf("Raw: expected 5 parts, got %d", len(parts))
	}
	if parts[0] == "" {
		t.Error("Raw: version field is empty")
	}
}

func TestRaw_GREASEFilteredInCiphers(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{0x0a0a, 0xc02b, 0xfafa}, // two GREASE + one real
	}
	raw := Raw(hello)
	parts := strings.SplitN(raw, ",", 5)
	ciphers := parts[1]

	// Only "49195" (0xc02b) should appear
	if strings.Contains(ciphers, "2570") {
		t.Errorf("GREASE 0x0a0a leaked into ciphers field: %q", ciphers)
	}
	if !strings.Contains(ciphers, "49195") {
		t.Errorf("non-GREASE cipher 0xc02b missing from ciphers field: %q", ciphers)
	}
}

// Compute — determinism and format

func TestCompute_Deterministic(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02b, 0xc02c},
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedCurves:   []tls.CurveID{tls.X25519},
		SupportedPoints:   []uint8{0},
		ServerName:        "example.com",
	}
	a := Compute(hello)
	b := Compute(hello)
	if a != b {
		t.Errorf("Compute not deterministic: %q != %q", a, b)
	}
}

func TestCompute_IsMD5Hex(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "test.com",
	}
	fp := Compute(hello)
	if len(fp) != 32 {
		t.Errorf("Compute: expected 32-char MD5 hex, got len=%d %q", len(fp), fp)
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Compute: non-hex character %q in %q", c, fp)
			break
		}
	}
}

func TestCompute_DifferentHellosDiffer(t *testing.T) {
	hello1 := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "a.com",
	}
	hello2 := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02c},
		SupportedVersions: []uint16{tls.VersionTLS12},
		ServerName:        "b.com",
	}
	fp1 := Compute(hello1)
	fp2 := Compute(hello2)
	if fp1 == fp2 {
		t.Error("different ClientHellos produced the same JA3 fingerprint")
	}
}

// Store — Get / Evict / InjectHello

func TestStore_SetAndGet(t *testing.T) {
	const addr = "1.2.3.4:9999"
	store.set(addr, "testhash", "testraw")

	hash, ok := Get(addr)
	if !ok {
		t.Fatal("Get: expected ok=true after set")
	}
	if hash != "testhash" {
		t.Errorf("Get: hash=%q, want %q", hash, "testhash")
	}

	raw, ok := GetRaw(addr)
	if !ok {
		t.Fatal("GetRaw: expected ok=true after set")
	}
	if raw != "testraw" {
		t.Errorf("GetRaw: raw=%q, want %q", raw, "testraw")
	}

	Evict(addr)
	_, ok = Get(addr)
	if ok {
		t.Error("Get: expected ok=false after Evict")
	}
}

func TestStore_GetMiss(t *testing.T) {
	_, ok := Get("not.a.real.addr:1")
	if ok {
		t.Error("Get: expected ok=false for unknown address")
	}
}

func TestStore_Evict_Idempotent(t *testing.T) {
	Evict("nonexistent:1") // must not panic
}

func TestStore_Sweep(t *testing.T) {
	// Directly insert a stale entry
	store.mu.Lock()
	store.entries["stale:1"] = entry{hash: "x", raw: "y", at: store.entries["stale:1"].at}
	store.mu.Unlock()

	// Force sweep — stale entry has zero time which is > ttl in the past
	store.sweep()

	_, ok := Get("stale:1")
	if ok {
		t.Error("sweep: stale entry should have been removed")
	}
}

func TestInjectHello_NilSafe(t *testing.T) {
	InjectHello(nil) // must not panic
}

// GREASE table completeness

func TestGreaseTable_AllValues(t *testing.T) {
	// RFC 8701 defines 16 GREASE values: 0x?a?a for ? in 0..f
	expected := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range expected {
		if !greaseTable[v] {
			t.Errorf("GREASE value %04x missing from greaseTable", v)
		}
	}
	if len(greaseTable) != 16 {
		t.Errorf("greaseTable has %d entries, want 16", len(greaseTable))
	}
}

// containsVersion

func TestContainsVersion(t *testing.T) {
	versions := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	if !containsVersion(versions, tls.VersionTLS13) {
		t.Error("containsVersion: should find TLS 1.3")
	}
	if containsVersion(versions, 0x0301) {
		t.Error("containsVersion: should not find TLS 1.0")
	}
	if containsVersion(nil, tls.VersionTLS13) {
		t.Error("containsVersion: nil slice should return false")
	}
}
