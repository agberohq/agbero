package firewall

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		_, _ = io.ReadAll(r.Body)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
})

func createTestEngine(t *testing.T, cfg *alaye.Firewall) *Engine {
	dir, err := os.MkdirTemp("", "firewall_test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	// Manually compile regexes for tests as validation isn't run here
	for _, r := range cfg.Rules {
		if r.Match != nil {
			if r.Match.Extract != nil && r.Match.Extract.Pattern != "" {
				r.Match.Extract.Regex = regexp.MustCompile(r.Match.Extract.Pattern)
			}
			compileConditions(r.Match.Any)
			compileConditions(r.Match.All)
			compileConditions(r.Match.None)
		}
	}

	e, err := New(cfg, woos.NewFolder(dir), ll.New("test").Disable())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func compileConditions(conds []*alaye.Condition) {
	for _, c := range conds {
		if c.Pattern != "" {
			c.Compiled = regexp.MustCompile(c.Pattern)
		}
	}
}

func TestStaticRules(t *testing.T) {
	cfg := &alaye.Firewall{
		Enabled: true,
		Rules: []*alaye.Rule{
			{
				Name: "whitelist_admin",
				Type: "whitelist",
				Match: &alaye.Match{
					IP: []string{"10.0.0.5"},
				},
			},
			{
				Name: "blacklist_bot",
				Type: "static",
				Match: &alaye.Match{
					IP: []string{"1.2.3.4", "5.0.0.0/8"},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	tests := []struct {
		ip   string
		code int
	}{
		{"10.0.0.5", 200},    // Whitelisted
		{"1.2.3.4", 403},     // Blacklisted exact
		{"5.1.2.3", 403},     // Blacklisted CIDR
		{"192.168.1.1", 200}, // Normal
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("IP %s: expected %d, got %d", tc.ip, tc.code, rec.Code)
		}
	}
}

func TestDynamicRules_Logic(t *testing.T) {
	// Rule: Block if (Header X-Test=BlockMe) OR (Query evil=true)
	cfg := &alaye.Firewall{
		Enabled: true,
		Rules: []*alaye.Rule{
			{
				Name: "bad_req",
				Type: "dynamic",
				Match: &alaye.Match{
					Any: []*alaye.Condition{
						{Location: "header", Key: "X-Test", Value: "BlockMe"},
						{Location: "query", Key: "evil", Value: "true"},
					},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	// Case 1: Match Header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Test", "BlockMe")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Error("Any: Header match failed")
	}

	// Case 2: Match Query
	req = httptest.NewRequest("GET", "/?evil=true", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Error("Any: Query match failed")
	}

	// Case 3: No Match
	req = httptest.NewRequest("GET", "/", nil)
	// Headers and Query are empty, so no condition in Any should match.
	// checkMatch should return false.
	// Handler should proceed to next (200).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Error("Any: False positive. Request matched but should not have.")
	}
}

func TestBodyInspection(t *testing.T) {
	cfg := &alaye.Firewall{
		Enabled:             true,
		InspectBody:         true,
		MaxInspectBytes:     1024,
		InspectContentTypes: []string{"application/json"},
		Rules: []*alaye.Rule{
			{
				Name: "sql_injection",
				Type: "dynamic",
				Match: &alaye.Match{
					Any: []*alaye.Condition{
						{Location: "body", Pattern: "(?i)union.*select"},
					},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	// Case 1: Malicious Body
	body := bytes.NewBufferString(`{"q": "UNION SELECT * FROM users"}`)
	req := httptest.NewRequest("POST", "/api", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Error("Body match failed")
	}

	// Case 2: Safe Body
	body = bytes.NewBufferString(`{"q": "hello world"}`)
	req = httptest.NewRequest("POST", "/api", body)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Error("Body false positive")
	}

	// Case 3: Ignored Content-Type (Text contains malicious payload, but firewall should ignore)
	body = bytes.NewBufferString(`UNION SELECT`)
	req = httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", "text/plain") // Not in inspect list
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Error("Should ignore unlisted content-type")
	}
}

func TestThresholds(t *testing.T) {
	// Rule: Allow 2 requests per minute, block on 3rd
	cfg := &alaye.Firewall{
		Enabled: true,
		Rules: []*alaye.Rule{
			{
				Name: "rate_limit",
				Type: "dynamic",
				Match: &alaye.Match{
					Any: []*alaye.Condition{{Location: "path", Value: "/login"}},
					Threshold: &alaye.Threshold{
						Count:   3,
						Window:  alaye.Duration(1 * time.Minute),
						TrackBy: "ip",
					},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	ip := "1.2.3.4"

	// Req 1 (Pass)
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = ip + ":555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal("Req 1 blocked")
	}

	// Req 2 (Pass)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal("Req 2 blocked")
	}

	// Req 3 (Block - Threshold Reached)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("Req 3 not blocked (Threshold failed)")
	}

	// Req 4 (Block - Persisted)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("Req 4 not blocked (Persistence failed)")
	}
}

func TestRouteOverrides(t *testing.T) {
	// Global rule blocks /admin
	globalCfg := &alaye.Firewall{
		Enabled: true,
		Rules: []*alaye.Rule{
			{
				Name: "block_admin",
				Type: "dynamic",
				Match: &alaye.Match{
					Path: []string{"/admin"},
				},
			},
		},
	}

	e := createTestEngine(t, globalCfg)
	defer e.Close()

	// 1. Test Default Global (Blocked)
	req := httptest.NewRequest("GET", "/admin", nil)
	rec := httptest.NewRecorder()
	e.Handler(mockHandler, nil).ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Error("Global rule should apply")
	}

	// 2. Test Route Override (Ignore Global -> Allowed)
	routeFW := &alaye.RouteFirewall{
		Enabled:      true, // This ensures route logic runs
		IgnoreGlobal: true,
	}
	rec = httptest.NewRecorder()
	e.Handler(mockHandler, routeFW).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Error("Route override failed to ignore global")
	}

	// 3. Test Route Specific Rule (Block /secret)
	routeFW.Rules = []*alaye.Rule{
		{
			Name: "route_block",
			Type: "dynamic",
			Match: &alaye.Match{
				Path: []string{"/secret"},
			},
		},
	}
	reqSecret := httptest.NewRequest("GET", "/secret", nil)
	rec = httptest.NewRecorder()
	e.Handler(mockHandler, routeFW).ServeHTTP(rec, reqSecret)
	if rec.Code != 403 {
		t.Error("Route specific rule failed")
	}
}

func TestPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "persist")
	defer os.RemoveAll(dir)

	cfg := &alaye.Firewall{Enabled: true}
	e1, _ := New(cfg, woos.NewFolder(dir), ll.New("test").Disable())

	// Manually ban
	e1.Block("1.1.1.1", "manual", 1*time.Hour)
	e1.Close()

	// Re-open
	e2, _ := New(cfg, woos.NewFolder(dir), ll.New("test").Disable())
	defer e2.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:123"
	rec := httptest.NewRecorder()
	e2.Handler(mockHandler, nil).ServeHTTP(rec, req)

	if rec.Code != 403 {
		t.Error("Persistence failed: IP not blocked after restart")
	}
}
