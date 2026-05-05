package waf_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/waf"
	"github.com/olekukonko/ll"
)

// Helpers

func okBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
}

func newEngine(t *testing.T, cfg *alaye.WAF) *waf.Engine {
	t.Helper()
	e, err := waf.New(waf.Config{
		WAF:    cfg,
		Logger: ll.New("test-waf"),
	})
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	return e
}

func doRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Engine construction

func TestNew_NilConfig_ReturnsNil(t *testing.T) {
	e, err := waf.New(waf.Config{WAF: nil})
	if err != nil {
		t.Fatalf("nil WAF config should not error, got: %v", err)
	}
	if e != nil {
		t.Fatal("nil WAF config should return nil engine")
	}
}

func TestNew_DisabledWAF_ReturnsNil(t *testing.T) {
	e, err := waf.New(waf.Config{
		WAF: &alaye.WAF{Status: expect.Inactive},
	})
	if err != nil {
		t.Fatalf("disabled WAF should not error: %v", err)
	}
	if e != nil {
		t.Fatal("disabled WAF should return nil engine")
	}
}

func TestNew_ActiveWAF_ReturnsEngine(t *testing.T) {
	e := newEngine(t, &alaye.WAF{
		Status:     expect.Active,
		Driver:     "coraza",
		Mode:       "monitor",
		Directives: []string{"SecRuleEngine DetectionOnly"},
	})
	if e == nil {
		t.Fatal("active WAF should return non-nil engine")
	}
}

func TestNew_InvalidDirective_ReturnsError(t *testing.T) {
	_, err := waf.New(waf.Config{
		WAF: &alaye.WAF{
			Status:     expect.Active,
			Driver:     "coraza",
			Mode:       "active",
			Directives: []string{"NotARealDirective !!!"},
		},
		Logger: ll.New("test"),
	})
	if err == nil {
		t.Fatal("invalid Coraza directive should return error")
	}
}

// Nil engine is a safe passthrough

func TestEngine_Nil_IsPassthrough(t *testing.T) {
	var e *waf.Engine // nil
	h := e.Middleware(okBackend())

	w := doRequest(h, "GET", "/safe", "")
	if w.Code != http.StatusOK {
		t.Errorf("nil engine passthrough: want 200, got %d", w.Code)
	}
}

// Monitor mode — logs but never blocks

func TestEngine_MonitorMode_NeverBlocks(t *testing.T) {
	e := newEngine(t, &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "monitor",
		// Classic SQL-injection detection rule
		Directives: []string{
			"SecRuleEngine DetectionOnly",
			`SecRule ARGS "@contains <script>" "id:1001,phase:2,deny,status:403,msg:'XSS'"`,
		},
	})

	h := e.Middleware(okBackend())

	// XSS payload — would be blocked in active mode
	w := doRequest(h, "GET", "/?q=<script>alert(1)</script>", "")
	if w.Code != http.StatusOK {
		t.Errorf("monitor mode: want 200 (never block), got %d", w.Code)
	}
}

// Active mode — blocks matched requests

func TestEngine_ActiveMode_BlocksMatchedRequest(t *testing.T) {
	e := newEngine(t, &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "active",
		Directives: []string{
			"SecRuleEngine On",
			`SecRule ARGS "@contains badword" "id:1002,phase:2,deny,status:403,msg:'Blocked'"`,
		},
	})

	h := e.Middleware(okBackend())

	w := doRequest(h, "GET", "/?input=badword", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("active mode with matching rule: want 403, got %d", w.Code)
	}
}

func TestEngine_ActiveMode_AllowsCleanRequest(t *testing.T) {
	e := newEngine(t, &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "active",
		Directives: []string{
			"SecRuleEngine On",
			`SecRule ARGS "@contains badword" "id:1003,phase:2,deny,status:403,msg:'Blocked'"`,
		},
	})

	h := e.Middleware(okBackend())

	w := doRequest(h, "GET", "/?input=clean", "")
	if w.Code != http.StatusOK {
		t.Errorf("active mode with clean request: want 200, got %d", w.Code)
	}
}

// WAFRoute — IgnoreGlobal prevents global WAF from applying

func TestEngine_WAFRoute_IgnoreGlobal_DisablesGlobalWAF(t *testing.T) {
	globalWAF := &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "active",
		Directives: []string{
			"SecRuleEngine On",
			`SecRule ARGS "@contains badword" "id:1004,phase:2,deny,status:403,msg:'Blocked'"`,
		},
	}

	routeWAF := alaye.WAFRoute{
		Status:       expect.Active,
		IgnoreGlobal: true,
		// No rules — effectively disables WAF for this route
	}

	e, err := waf.NewForRoute(waf.RouteConfig{
		Global: globalWAF,
		Route:  &routeWAF,
		Logger: ll.New("test"),
	})
	if err != nil {
		t.Fatalf("NewForRoute: %v", err)
	}

	h := e.Middleware(okBackend())
	w := doRequest(h, "GET", "/?input=badword", "")

	// With IgnoreGlobal=true and no route rules, request should pass through
	if w.Code != http.StatusOK {
		t.Errorf("IgnoreGlobal=true with no route rules: want 200, got %d", w.Code)
	}
}

func TestEngine_WAFRoute_AddsRouteDirectives(t *testing.T) {
	routeWAF := alaye.WAFRoute{
		Status:       expect.Active,
		IgnoreGlobal: false,
		Directives: []string{
			"SecRuleEngine On",
			`SecRule ARGS "@contains routespecific" "id:2001,phase:2,deny,status:403,msg:'Route rule'"`,
		},
	}

	e, err := waf.NewForRoute(waf.RouteConfig{
		Global: &alaye.WAF{
			Status:     expect.Active,
			Driver:     "coraza",
			Mode:       "active",
			Directives: []string{"SecRuleEngine On"},
		},
		Route:  &routeWAF,
		Logger: ll.New("test"),
	})
	if err != nil {
		t.Fatalf("NewForRoute: %v", err)
	}

	h := e.Middleware(okBackend())

	// Route-specific rule blocks this
	w := doRequest(h, "GET", "/?x=routespecific", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("route directive: want 403, got %d", w.Code)
	}

	// Clean request passes
	w2 := doRequest(h, "GET", "/?x=clean", "")
	if w2.Code != http.StatusOK {
		t.Errorf("clean request: want 200, got %d", w2.Code)
	}
}

func TestEngine_WAFRoute_NilRoute_FallsBackToGlobal(t *testing.T) {
	globalWAF := &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "active",
		Directives: []string{
			"SecRuleEngine On",
			`SecRule ARGS "@contains blocked" "id:3001,phase:2,deny,status:403,msg:'Blocked'"`,
		},
	}

	e, err := waf.NewForRoute(waf.RouteConfig{
		Global: globalWAF,
		Route:  nil, // no per-route override
		Logger: ll.New("test"),
	})
	if err != nil {
		t.Fatalf("NewForRoute with nil route: %v", err)
	}

	h := e.Middleware(okBackend())
	w := doRequest(h, "GET", "/?x=blocked", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("nil route falls back to global: want 403, got %d", w.Code)
	}
}

// Middleware chaining — WAF is in the right position (before backend)

func TestEngine_Middleware_ChainOrder(t *testing.T) {
	// If WAF blocks, backend should never be called
	backendCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(200)
	})

	e := newEngine(t, &alaye.WAF{
		Status: expect.Active,
		Driver: "coraza",
		Mode:   "active",
		Directives: []string{
			"SecRuleEngine On",
			`SecRule REQUEST_URI "@contains /admin" "id:4001,phase:1,deny,status:403,msg:'No admin'"`,
		},
	})

	h := e.Middleware(backend)
	w := doRequest(h, "GET", "/admin/secret", "")

	if w.Code != http.StatusForbidden {
		t.Errorf("blocked path: want 403, got %d", w.Code)
	}
	if backendCalled {
		t.Error("backend should not be called when WAF blocks the request")
	}
}

// Transaction cleanup — no goroutine or memory leaks on clean requests

func TestEngine_TransactionCleanup_OnCleanRequest(t *testing.T) {
	e := newEngine(t, &alaye.WAF{
		Status:     expect.Active,
		Driver:     "coraza",
		Mode:       "active",
		Directives: []string{"SecRuleEngine On"},
	})
	h := e.Middleware(okBackend())

	// Run many requests to surface any leak (would panic or OOM if transactions leak)
	for i := 0; i < 100; i++ {
		w := doRequest(h, "GET", "/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, w.Code)
		}
	}
}
