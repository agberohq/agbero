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

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
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

	// Manually compile regexes and set up extract for tests as validation isn't run here
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Match.Enabled.Active() {
			compileConditions(r.Match.Any)
			compileConditions(r.Match.All)
			compileConditions(r.Match.None)

			// Set up Extract if enabled but regex is nil
			if r.Match.Extract != nil && r.Match.Extract.Enabled.Active() && r.Match.Extract.Regex == nil && r.Match.Extract.Pattern != "" {
				r.Match.Extract.Regex = regexp.MustCompile(r.Match.Extract.Pattern)
			}
		}
	}

	e, err := New(cfg, woos.NewFolder(dir), ll.New("test").Disable())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func compileConditions(conds []alaye.Condition) {
	for i := range conds {
		c := &conds[i]
		if c.Pattern != "" && c.Compiled == nil {
			c.Compiled = regexp.MustCompile(c.Pattern)
		}
	}
}

func TestStaticRules(t *testing.T) {
	cfg := &alaye.Firewall{
		Status: alaye.Active,
		Rules: []alaye.Rule{
			{
				Name: "whitelist_admin",
				Type: "whitelist",
				Match: alaye.Match{
					Enabled: alaye.Active,
					IP:      []string{"10.0.0.5"},
				},
			},
			{
				Name: "blacklist_bot",
				Type: "static",
				Match: alaye.Match{
					Enabled: alaye.Active,
					IP:      []string{"1.2.3.4", "5.0.0.0/8"},
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
	cfg := &alaye.Firewall{
		Status: alaye.Active,
		Rules: []alaye.Rule{
			{
				Name: "bad_req",
				Type: "dynamic",
				Match: alaye.Match{
					Enabled: alaye.Active,
					Any: []alaye.Condition{
						{Enabled: alaye.Active, Location: "header", Key: "X-Test", Value: "BlockMe"},
						{Enabled: alaye.Active, Location: "query", Key: "evil", Value: "true"},
					},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	// Case 1: Match Header -> Block IP 1.2.3.1
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.1:123"
	req.Header.Set("X-Test", "BlockMe")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("Any: Header match failed. Got %d", rec.Code)
	}

	// Case 2: Match Query -> Block IP 1.2.3.2 (Unique IP)
	req = httptest.NewRequest("GET", "/?evil=true", nil)
	req.RemoteAddr = "1.2.3.2:123"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("Any: Query match failed. Got %d", rec.Code)
	}

	// Case 3: Unknown Match -> Allow IP 1.2.3.3 (Unique IP)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.3:123"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("Any: NotActive positive. Got %d", rec.Code)
	}
}

func TestBodyInspection(t *testing.T) {
	cfg := &alaye.Firewall{
		Status:              alaye.Active,
		InspectBody:         true,
		MaxInspectBytes:     1024,
		InspectContentTypes: []string{"application/json"},
		Rules: []alaye.Rule{
			{
				Name: "sql_injection",
				Type: "dynamic",
				Match: alaye.Match{
					Enabled: alaye.Active,
					Any: []alaye.Condition{
						{Enabled: alaye.Active, Location: "body", Pattern: "(?i)union.*select"},
					},
				},
			},
		},
	}

	e := createTestEngine(t, cfg)
	defer e.Close()
	h := e.Handler(mockHandler, nil)

	// Case 1: Malicious Body (JSON) - Block 1.2.3.1
	body := bytes.NewBufferString(`{"q": "UNION SELECT * FROM users"}`)
	req := httptest.NewRequest("POST", "/api", body)
	req.RemoteAddr = "1.2.3.1:123"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("Body match failed. Got %d", rec.Code)
	}

	// Case 2: Safe Body - Allow 1.2.3.2
	body = bytes.NewBufferString(`{"q": "hello world"}`)
	req = httptest.NewRequest("POST", "/api", body)
	req.RemoteAddr = "1.2.3.2:123"
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("Body false positive. Got %d", rec.Code)
	}

	// Case 3: Malicious Content but Ignored Type - Allow 1.2.3.3
	body = bytes.NewBufferString(`UNION SELECT`)
	req = httptest.NewRequest("POST", "/upload", body)
	req.RemoteAddr = "1.2.3.3:123"
	req.Header.Set("Content-Type", "text/plain")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("Should ignore unlisted content-type. Got %d", rec.Code)
	}
}

func TestThresholds(t *testing.T) {
	cfg := &alaye.Firewall{
		Status: alaye.Active,
		Rules: []alaye.Rule{
			{
				Name: "rate_limit",
				Type: "dynamic",
				Match: alaye.Match{
					Enabled: alaye.Active,
					// Match everything
					Any: []alaye.Condition{{Enabled: alaye.Active, Location: "path", Operator: "prefix", Value: "/"}},
					Threshold: &alaye.Threshold{
						Enabled: alaye.Active,
						Count:   3,
						Window:  1 * time.Minute,
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
		t.Fatalf("Req 1 blocked: %d", rec.Code)
	}

	// Req 2 (Pass)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Req 2 blocked: %d", rec.Code)
	}

	// Req 3 (Block - Threshold Reached)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Req 3 not blocked (Threshold failed): %d", rec.Code)
	}

	// Req 4 (Block - Persisted)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Req 4 not blocked (Persistence failed): %d", rec.Code)
	}
}

func TestPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "persist")
	defer os.RemoveAll(dir)

	cfg := &alaye.Firewall{Status: alaye.Active}
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

func TestRouteOverrides(t *testing.T) {
	// Global: Block /admin
	globalCfg := &alaye.Firewall{
		Status: alaye.Active,
		Rules: []alaye.Rule{
			{
				Name: "block_admin",
				Type: "dynamic",
				Match: alaye.Match{
					Enabled: alaye.Active,
					Path:    []string{"/admin"},
				},
			},
		},
	}

	e := createTestEngine(t, globalCfg)
	defer e.Close()

	// 1. Default Global (Block) -> 1.2.3.1
	req := httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "1.2.3.1:123"
	rec := httptest.NewRecorder()
	e.Handler(mockHandler, nil).ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Error("Global rule should apply")
	}

	// 2. Route Ignore Global (Allow) -> 1.2.3.2
	routeFW := &alaye.FirewallRoute{
		Status:       alaye.Active,
		IgnoreGlobal: true,
	}
	req = httptest.NewRequest("GET", "/admin", nil)
	req.RemoteAddr = "1.2.3.2:123"
	rec = httptest.NewRecorder()
	e.Handler(mockHandler, routeFW).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Error("Route override failed to ignore global")
	}

	// 3. Route Specific Rule (Block /secret) -> 1.2.3.3
	routeFW.Rules = []alaye.Rule{
		{
			Name: "route_block",
			Type: "dynamic",
			Match: alaye.Match{
				Enabled: alaye.Active,
				Path:    []string{"/secret"},
			},
		},
	}
	reqSecret := httptest.NewRequest("GET", "/secret", nil)
	reqSecret.RemoteAddr = "1.2.3.3:123"
	rec = httptest.NewRecorder()
	e.Handler(mockHandler, routeFW).ServeHTTP(rec, reqSecret)
	if rec.Code != 403 {
		t.Error("Route specific rule failed")
	}
}

func TestConditions_Table(t *testing.T) {
	tests := []struct {
		name      string
		cond      alaye.Condition
		reqURL    string
		reqHeader map[string]string
		reqMethod string
		want      bool
	}{
		{
			name:   "Prefix Match",
			cond:   alaye.Condition{Enabled: alaye.Active, Location: "path", Operator: "prefix", Value: "/api"},
			reqURL: "/api/v1/users",
			want:   true,
		},
		{
			name:   "Suffix Match",
			cond:   alaye.Condition{Enabled: alaye.Active, Location: "path", Operator: "suffix", Value: ".php"},
			reqURL: "/index.php",
			want:   true,
		},
		{
			name:   "Contains Match",
			cond:   alaye.Condition{Enabled: alaye.Active, Location: "path", Operator: "contains", Value: "admin"},
			reqURL: "/v1/admin/login",
			want:   true,
		},
		{
			name:      "Header Missing (True)",
			cond:      alaye.Condition{Enabled: alaye.Active, Location: "header", Key: "X-Auth", Operator: "missing"},
			reqURL:    "/",
			reqHeader: map[string]string{}, // Empty
			want:      true,
		},
		{
			name:      "Header Missing (NotActive)",
			cond:      alaye.Condition{Enabled: alaye.Active, Location: "header", Key: "X-Auth", Operator: "missing"},
			reqURL:    "/",
			reqHeader: map[string]string{"X-Auth": "123"},
			want:      false,
		},
		{
			name:      "Method Exact",
			cond:      alaye.Condition{Enabled: alaye.Active, Location: "method", Value: "POST"},
			reqURL:    "/",
			reqMethod: "POST",
			want:      true,
		},
		{
			name:      "Method IgnoreCase",
			cond:      alaye.Condition{Enabled: alaye.Active, Location: "method", Value: "post", IgnoreCase: true},
			reqURL:    "/",
			reqMethod: "POST",
			want:      true,
		},
		{
			name:   "Negate Match",
			cond:   alaye.Condition{Enabled: alaye.Active, Location: "path", Value: "/safe", Negate: true},
			reqURL: "/safe",
			want:   false,
		},
	}

	cfg := &alaye.Firewall{Status: alaye.Active}
	e := createTestEngine(t, cfg)
	defer e.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.reqMethod, tc.reqURL, nil)
			if tc.reqMethod == "" {
				req.Method = "GET"
			}
			for k, v := range tc.reqHeader {
				req.Header.Set(k, v)
			}

			insp := &Inspector{
				Req: req,
				IP:  "1.2.3.4",
			}
			got := e.checkCondition(tc.cond, insp)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
