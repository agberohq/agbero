package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/ja3"
	"github.com/olekukonko/ll"
)

// Helpers

const (
	knownFP     = "aabbccddeeff00112233445566778899"
	unknownFP   = "00000000000000000000000000000000"
	anotherFP   = "ffffffffffffffffffffffffffffffff"
	testRemAddr = "192.0.2.1:54321"
)

// newTestEngine creates a minimal firewall Engine suitable for unit tests.
func newTestEngine(t *testing.T, rules []alaye.Rule) *Engine {
	t.Helper()
	dir := expect.NewFolder(t.TempDir())
	fw := &alaye.Firewall{
		Status: expect.Active,
		Mode:   "active",
		Rules:  rules,
	}
	engine, err := New(Config{
		Firewall: fw,
		DataDir:  dir,
		Logger:   ll.New("test").Disable(),
	})
	if err != nil {
		t.Fatalf("firewall.New: %v", err)
	}
	return engine
}

// newRequestWithFingerprint builds a test request with the given remote addr
// and pre-seeds the ja3 store so the firewall sees the fingerprint.
func newRequestWithFingerprint(fp string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = testRemAddr
	if fp != "" {
		ja3.SetForTest(testRemAddr, fp)
	}
	return req
}

func TestMatch_Validate_JA3Mode_Valid(t *testing.T) {
	cases := []string{"", "deny", "allow"}
	for _, mode := range cases {
		m := alaye.Match{
			Enabled: expect.Active,
			JA3:     []string{knownFP},
			JA3Mode: mode,
		}
		if err := m.Validate(); err != nil {
			t.Errorf("JA3Mode=%q: unexpected error: %v", mode, err)
		}
	}
}

func TestMatch_Validate_JA3Mode_Invalid(t *testing.T) {
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "block", // unsupported value
	}
	if err := m.Validate(); err == nil {
		t.Error("expected error for unsupported JA3Mode, got nil")
	}
}

func TestMatch_Validate_EmptyJA3_NoMode_Valid(t *testing.T) {
	// JA3 list empty — JA3Mode field irrelevant, validation should pass
	m := alaye.Match{Enabled: expect.Active}
	if err := m.Validate(); err != nil {
		t.Errorf("empty JA3 unexpected error: %v", err)
	}
}

// checkMatch — JA3 deny mode (default)

func TestCheckMatch_JA3_Deny_Match(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		ParsedIP:    nil,
		Fingerprint: knownFP,
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "deny",
	}
	if !engine.checkMatch(m, in) {
		t.Error("deny mode: fingerprint in list should return true (block)")
	}
}

func TestCheckMatch_JA3_Deny_Miss(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: unknownFP,
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "deny",
	}
	if engine.checkMatch(m, in) {
		t.Error("deny mode: fingerprint NOT in list should return false (allow)")
	}
}

func TestCheckMatch_JA3_Deny_DefaultMode(t *testing.T) {
	// Empty JA3Mode defaults to "deny"
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: knownFP,
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "", // empty → deny
	}
	if !engine.checkMatch(m, in) {
		t.Error("default (empty) JA3Mode: fingerprint in list should block")
	}
}

// checkMatch — JA3 allow mode (allowlist)

func TestCheckMatch_JA3_Allow_Allowed(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: knownFP, // in the allowlist
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "allow",
	}
	// Fingerprint IS in allowlist → client is allowed → checkMatch returns false (no block)
	if engine.checkMatch(m, in) {
		t.Error("allow mode: fingerprint in list should return false (pass through)")
	}
}

func TestCheckMatch_JA3_Allow_Blocked(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: unknownFP, // NOT in the allowlist
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "allow",
	}
	// Fingerprint NOT in allowlist → block → checkMatch returns true
	if !engine.checkMatch(m, in) {
		t.Error("allow mode: fingerprint NOT in list should return true (block)")
	}
}

// checkMatch — plain HTTP (no fingerprint)

func TestCheckMatch_JA3_EmptyFingerprint_Skipped(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: "", // plain HTTP — no fingerprint
		Logger:      ll.New("test").Disable(),
	}

	// Deny rule against knownFP — must not fire for plain HTTP
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP},
		JA3Mode: "deny",
	}
	if engine.checkMatch(m, in) {
		t.Error("JA3 deny rule must not fire for plain HTTP (empty fingerprint)")
	}

	// Allow rule — must not fire for plain HTTP either (no fingerprint means skip)
	m.JA3Mode = "allow"
	if engine.checkMatch(m, in) {
		t.Error("JA3 allow rule must not fire for plain HTTP (empty fingerprint)")
	}
}

// checkMatch — multiple fingerprints in list

func TestCheckMatch_JA3_MultipleInList(t *testing.T) {
	engine := newTestEngine(t, nil)
	in := &Inspector{
		Req:         httptest.NewRequest(http.MethodGet, "/", nil),
		IP:          "1.2.3.4",
		Fingerprint: anotherFP,
		Logger:      ll.New("test").Disable(),
	}
	m := alaye.Match{
		Enabled: expect.Active,
		JA3:     []string{knownFP, unknownFP, anotherFP},
		JA3Mode: "deny",
	}
	if !engine.checkMatch(m, in) {
		t.Error("deny: fingerprint matching any list entry should block")
	}
}

func TestHandler_JA3_DenyBlocks(t *testing.T) {
	rules := []alaye.Rule{
		{
			Name:   "block-known-fp",
			Type:   "static",
			Action: "block",
			Match: alaye.Match{
				Enabled: expect.Active,
				JA3:     []string{knownFP},
				JA3Mode: "deny",
			},
		},
	}
	engine := newTestEngine(t, rules)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := engine.Handler(next, nil)

	// Seed the fingerprint store
	ja3.SetForTest(testRemAddr, knownFP)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = testRemAddr
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("next handler should not be called for blocked JA3 fingerprint")
	}
	// Blocked request must return non-200
	if w.Code == http.StatusOK {
		t.Errorf("expected non-200 for blocked fingerprint, got %d", w.Code)
	}
}

func TestHandler_JA3_AllowedPassesThrough(t *testing.T) {
	rules := []alaye.Rule{
		{
			Name:   "block-known-fp",
			Type:   "static",
			Action: "block",
			Match: alaye.Match{
				Enabled: expect.Active,
				JA3:     []string{knownFP},
				JA3Mode: "deny",
			},
		},
	}
	engine := newTestEngine(t, rules)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := engine.Handler(next, nil)

	// Different fingerprint — not in the deny list
	ja3.SetForTest(testRemAddr, unknownFP)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = testRemAddr
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called for non-blocked fingerprint")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed fingerprint, got %d", w.Code)
	}
}

func TestHandler_JA3_PlainHTTP_NotBlocked(t *testing.T) {
	// Rule with JA3 deny — must not block plain HTTP (no fingerprint stored)
	rules := []alaye.Rule{
		{
			Name:   "block-fp",
			Type:   "static",
			Action: "block",
			Match: alaye.Match{
				Enabled: expect.Active,
				JA3:     []string{knownFP},
			},
		},
	}
	engine := newTestEngine(t, rules)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := engine.Handler(next, nil)

	// Plain HTTP request — no fingerprint in store
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("plain HTTP must not be blocked by JA3 deny rule")
	}
}

func TestHandler_NoFirewall_NilEngine(t *testing.T) {
	// Nil engine must pass through — Handler is a no-op
	var engine *Engine
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := engine.Handler(next, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called {
		t.Error("nil engine: next handler should always be called")
	}
}
