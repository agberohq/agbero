package xserverless

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/orchestrator"
	resource "github.com/agberohq/agbero/internal/hub/resource"
)

// Helpers

func newResource(t *testing.T) *resource.Resource {
	t.Helper()
	res := resource.New()
	t.Cleanup(func() { res.Close() })
	return res
}

func newProxy(t *testing.T) resource.Proxy {
	t.Helper()
	return resource.Proxy{Resource: newResource(t)}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// upstream spins up a test server and registers a cleanup. Returns the server.
func upstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// Provided regression test — preserved verbatim

// TestServerless_New_NoPanicOnCollision verifies that duplicate registrations
// do not cause a ServeMux panic. It ensures that REST and Worker name
// collisions are handled gracefully based on priority rules.
func TestServerless_New_NoPanicOnCollision(t *testing.T) {
	res := resource.New()
	defer res.Close()

	route := alaye.Route{
		Env: map[string]expect.Value{},
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{
				{Name: "duplicate", Enabled: expect.Active, URL: "http://first"},
				{Name: "duplicate", Enabled: expect.Active, URL: "http://second"},
				{Name: "conflict", Enabled: expect.Active, URL: "http://rest-wins"},
			},
			Workers: []alaye.Work{
				{Name: "worker-dup", Command: []string{"echo", "1"}},
				{Name: "worker-dup", Command: []string{"echo", "2"}},
				{Name: "conflict", Command: []string{"echo", "worker-loses"}},
			},
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked due to collision: %v", r)
		}
	}()

	handler := New(resource.Proxy{Resource: res}, &route)
	if handler == nil {
		t.Fatal("expected handler, got nil")
	}
}

// Routing — unknown paths return 404

func TestServerless_UnknownPath_404(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay:  []alaye.Replay{{Name: "api", Enabled: expect.Active, URL: srv.URL}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestServerless_EmptyServerless_404(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{Enabled: expect.Active},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/anything")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for empty serverless block, got %d", w.Code, w.Code)
	}
}

// serveFixed — replay with a static upstream URL

func TestReplay_Fixed_ProxiesRequest(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-response")
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay:  []alaye.Replay{{Name: "svc", Enabled: expect.Active, URL: srv.URL}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/svc")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "upstream-response" {
		t.Errorf("body = %q, want %q", w.Body.String(), "upstream-response")
	}
}

func TestReplay_Fixed_InjectsConfiguredQueryParams(t *testing.T) {
	var capturedQuery url.Values
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "svc",
				Enabled: expect.Active,
				URL:     srv.URL,
				Query:   map[string]expect.Value{"apikey": "secret123"},
			}},
		},
	}
	h := New(newProxy(t), route)
	get(t, h, "/svc")
	if capturedQuery.Get("apikey") != "secret123" {
		t.Errorf("apikey query param = %q, want %q", capturedQuery.Get("apikey"), "secret123")
	}
}

func TestReplay_Fixed_ForwardsClientQueryParams(t *testing.T) {
	var capturedQuery url.Values
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:         "svc",
				Enabled:      expect.Active,
				URL:          srv.URL,
				ForwardQuery: expect.Active,
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/svc?user=alice&page=2", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedQuery.Get("user") != "alice" {
		t.Errorf("forwarded user = %q, want alice", capturedQuery.Get("user"))
	}
	if capturedQuery.Get("page") != "2" {
		t.Errorf("forwarded page = %q, want 2", capturedQuery.Get("page"))
	}
}

func TestReplay_Fixed_InjectsConfiguredHeaders(t *testing.T) {
	var capturedHeader string
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Service-Token")
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "svc",
				Enabled: expect.Active,
				URL:     srv.URL,
				Headers: map[string]string{"X-Service-Token": "tok-xyz"},
			}},
		},
	}
	h := New(newProxy(t), route)
	get(t, h, "/svc")
	if capturedHeader != "tok-xyz" {
		t.Errorf("X-Service-Token = %q, want tok-xyz", capturedHeader)
	}
}

func TestReplay_Fixed_MethodNotAllowed(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "svc",
				Enabled: expect.Active,
				URL:     srv.URL,
				Methods: []string{"POST"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/svc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestReplay_Fixed_UpstreamError_Returns502(t *testing.T) {
	// Point at a port nothing listens on.
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "svc",
				Enabled: expect.Active,
				URL:     "http://127.0.0.1:19999",
			}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/svc")
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

func TestReplay_Fixed_DisabledEndpoint_NotRegistered(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "hidden",
				Enabled: expect.Inactive,
				URL:     "http://should-not-matter",
			}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/hidden")
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled endpoint should not be registered, got %d", w.Code)
	}
}

// serveReplay — dynamic mode (URL supplied per-request)

func TestReplay_Dynamic_MissingURL_Returns400(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:    "proxy",
				Enabled: expect.Active,
				// URL == "" → replay mode
				AllowedDomains: []string{"*"},
			}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/proxy") // no X-Agbero-Replay-Url header
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestReplay_Dynamic_URLViaHeader_ProxiesRequest(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "dynamic-response")
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"127.0.0.1"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, srv.URL)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "dynamic-response" {
		t.Errorf("body = %q, want %q", w.Body.String(), "dynamic-response")
	}
}

func TestReplay_Dynamic_URLViaQueryParam_ProxiesRequest(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "via-queryparam")
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"127.0.0.1"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+url.QueryEscape(srv.URL), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "via-queryparam" {
		t.Errorf("body = %q, want via-queryparam", w.Body.String())
	}
}

// TestReplay_Dynamic_InjectsConfiguredQueryParams is the regression test for
// Bug #2: serveReplay was not calling prepareURL, so configured query params
// (e.g. API keys) were silently dropped in dynamic replay mode.
func TestReplay_Dynamic_InjectsConfiguredQueryParams(t *testing.T) {
	var capturedQuery url.Values
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"127.0.0.1"},
				// These must reach the upstream even in dynamic mode.
				Query: map[string]expect.Value{"apikey": "secret"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, srv.URL)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedQuery.Get("apikey") != "secret" {
		t.Errorf("apikey = %q, want %q — prepareURL not called in serveReplay", capturedQuery.Get("apikey"), "secret")
	}
}

// TestReplay_Dynamic_ForwardsClientQueryParams verifies that forward_query = true
// works in dynamic replay mode (also relying on the prepareURL fix).
func TestReplay_Dynamic_ForwardsClientQueryParams(t *testing.T) {
	var capturedQuery url.Values
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"127.0.0.1"},
				ForwardQuery:   expect.Active,
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy?token=abc&page=3", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, srv.URL)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedQuery.Get("token") != "abc" {
		t.Errorf("forwarded token = %q, want abc", capturedQuery.Get("token"))
	}
	if capturedQuery.Get("page") != "3" {
		t.Errorf("forwarded page = %q, want 3", capturedQuery.Get("page"))
	}
}

// TestReplay_Dynamic_ConfigAndClientQueryParams_BothPresent verifies that when
// both configured query params and client query params are present, both sets
// arrive at the upstream (configured params take precedence on key conflicts).
func TestReplay_Dynamic_ConfigAndClientQueryParams_BothPresent(t *testing.T) {
	var capturedQuery url.Values
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"127.0.0.1"},
				ForwardQuery:   expect.Active,
				Query:          map[string]expect.Value{"apikey": "fixed-key"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy?search=foo", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, srv.URL)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedQuery.Get("apikey") != "fixed-key" {
		t.Errorf("configured apikey = %q, want fixed-key", capturedQuery.Get("apikey"))
	}
	if capturedQuery.Get("search") != "foo" {
		t.Errorf("forwarded search = %q, want foo", capturedQuery.Get("search"))
	}
}

func TestReplay_Dynamic_DisallowedHost_Returns403(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"allowed.example.com"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, "http://notallowed.example.com/path")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for disallowed host", w.Code)
	}
}

func TestReplay_Dynamic_InvalidURL_Returns400(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"*"},
			}},
		},
	}
	h := New(newProxy(t), route)

	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set(def.HeaderXAgberoReplayURL, "://bad-url")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid URL", w.Code)
	}
}

func TestReplay_Dynamic_NonHTTPScheme_Returns400(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{{
				Name:           "proxy",
				Enabled:        expect.Active,
				AllowedDomains: []string{"*"},
			}},
		},
	}
	h := New(newProxy(t), route)

	for _, badURL := range []string{"ftp://example.com/file", "file:///etc/passwd"} {
		req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
		req.Header.Set(def.HeaderXAgberoReplayURL, badURL)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("URL %q: status = %d, want 400", badURL, w.Code)
		}
	}
}

// cleanRouteName

func TestCleanRouteName(t *testing.T) {
	tests := []struct {
		input  string
		want   string
		wantOK bool
	}{
		{"api", "api", true},
		{"my-service", "my-service", true},
		{"svc.v2", "svc.v2", true},
		{"svc_name", "svc_name", true},
		{"", "", false},
		{".", "", false},
		// path.Clean("/" + "../escape") → "/escape" — traversal is neutralised,
		// the resulting name "escape" is valid.
		{"../escape", "escape", true},
		{"has/slash", "", false},
		{"-starts-dash", "", false},
		// digits are in [a-zA-Z0-9] so a leading digit is allowed.
		{"0numeric", "0numeric", true},
		{"has space", "", false},
		{"has@at", "", false},
	}

	for _, tt := range tests {
		got, ok := cleanRouteName(tt.input)
		if ok != tt.wantOK {
			t.Errorf("cleanRouteName(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("cleanRouteName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Multiple endpoints registered on the same handler

func TestServerless_MultipleReplays_RoutedCorrectly(t *testing.T) {
	svc1 := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "svc1")
	})
	svc2 := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "svc2")
	})

	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay: []alaye.Replay{
				{Name: "svc1", Enabled: expect.Active, URL: svc1.URL},
				{Name: "svc2", Enabled: expect.Active, URL: svc2.URL},
			},
		},
	}
	h := New(newProxy(t), route)

	if w := get(t, h, "/svc1"); w.Body.String() != "svc1" {
		t.Errorf("/svc1 body = %q, want svc1", w.Body.String())
	}
	if w := get(t, h, "/svc2"); w.Body.String() != "svc2" {
		t.Errorf("/svc2 body = %q, want svc2", w.Body.String())
	}
}

func TestServerless_REST_TakesPriorityOverWorker_OnNameCollision(t *testing.T) {
	srv := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "rest-wins")
	})

	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Replay:  []alaye.Replay{{Name: "conflict", Enabled: expect.Active, URL: srv.URL}},
			Workers: []alaye.Work{{Name: "conflict", Enabled: expect.Active, Command: []string{"echo", "worker-loses"}}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/conflict")
	if w.Body.String() != "rest-wins" {
		t.Errorf("body = %q, want rest-wins (REST must take priority over Worker on name collision)", w.Body.String())
	}
}

// Worker dispatch

func TestWorker_NilOrchestrator_Returns500(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Workers: []alaye.Work{{
				Name:    "echo",
				Enabled: expect.Active,
				Command: []string{"echo", "hello"},
			}},
		},
	}
	// resource.Proxy has no Orch set → nil orchestrator
	h := New(newProxy(t), route)
	w := get(t, h, "/echo")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when orchestrator is nil", w.Code)
	}
}

func TestWorker_WithOrchestrator_ExecutesCommand(t *testing.T) {
	if _, err := os.LookupEnv("CI"); false && err {
		t.Skip("skipping exec test in CI")
	}

	uniqueOutput := fmt.Sprintf("worker-output-%d", time.Now().UnixNano())

	proxy := newProxy(t)
	proxy.Orch = orchestrator.New(orchestrator.Config{
		Logger:          proxy.Resource.Logger,
		WorkDir:         expect.NewFolder(t.TempDir()),
		AllowedCommands: []string{"sh"},
	})

	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Workers: []alaye.Work{{
				Name:     "echo",
				Enabled:  expect.Active,
				Command:  []string{"sh", "-c", fmt.Sprintf(`printf '%s'`, uniqueOutput)},
				Landlock: expect.Inactive,
			}},
		},
	}
	h := New(proxy, route)
	w := get(t, h, "/echo")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), uniqueOutput) {
		t.Errorf("body = %q, want it to contain %q", w.Body.String(), uniqueOutput)
	}
}

func TestWorker_Disabled_NotRegistered(t *testing.T) {
	route := &alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: expect.Active,
			Workers: []alaye.Work{{
				Name:    "hidden",
				Enabled: expect.Inactive,
				Command: []string{"echo", "nope"},
			}},
		},
	}
	h := New(newProxy(t), route)
	w := get(t, h, "/hidden")
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled worker should not be registered, got %d", w.Code)
	}
}

// prepareURL unit tests — query injection logic in isolation

func TestPrepareURL_InjectsConfiguredParams(t *testing.T) {
	r := &Replay{
		cfg: alaye.Replay{
			Query: map[string]expect.Value{"key": "value"},
		},
	}
	u, _ := url.Parse("http://example.com/path")
	r.prepareURL(u, url.Values{})
	if u.Query().Get("key") != "value" {
		t.Errorf("key = %q, want value", u.Query().Get("key"))
	}
}

func TestPrepareURL_ForwardsClientParams_WhenEnabled(t *testing.T) {
	r := &Replay{
		cfg: alaye.Replay{
			ForwardQuery: expect.Active,
		},
	}
	u, _ := url.Parse("http://example.com/path")
	incoming := url.Values{"search": []string{"gopher"}}
	r.prepareURL(u, incoming)
	if u.Query().Get("search") != "gopher" {
		t.Errorf("search = %q, want gopher", u.Query().Get("search"))
	}
}

func TestPrepareURL_DoesNotForwardClientParams_WhenDisabled(t *testing.T) {
	r := &Replay{
		cfg: alaye.Replay{
			ForwardQuery: expect.Inactive,
		},
	}
	u, _ := url.Parse("http://example.com/path")
	r.prepareURL(u, url.Values{"secret": []string{"leaked"}})
	if u.Query().Get("secret") != "" {
		t.Errorf("secret should not be forwarded when forward_query is inactive, got %q", u.Query().Get("secret"))
	}
}

func TestPrepareURL_PreservesExistingURLParams(t *testing.T) {
	r := &Replay{
		cfg: alaye.Replay{
			Query: map[string]expect.Value{"added": "yes"},
		},
	}
	u, _ := url.Parse("http://example.com/path?existing=kept")
	r.prepareURL(u, url.Values{})
	q := u.Query()
	if q.Get("existing") != "kept" {
		t.Errorf("existing = %q, want kept", q.Get("existing"))
	}
	if q.Get("added") != "yes" {
		t.Errorf("added = %q, want yes", q.Get("added"))
	}
}
