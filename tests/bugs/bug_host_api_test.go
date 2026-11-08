package bugs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/operation/api"
	"github.com/go-chi/chi/v5"
)

// newHostAPI mounts the real admin host API (internal/operation/api) on an
// in-memory chi router backed by a temp hosts directory.
func newHostAPI(t *testing.T) (http.Handler, *discovery.Host, string) {
	t.Helper()

	tmp := t.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmp, "hosts"))
	if err := hostsDir.Init(expect.DirPerm); err != nil {
		t.Fatalf("mkdir hosts: %v", err)
	}

	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("prime host manager: %v", err)
	}

	shared := &api.Shared{Logger: testLogger, Discovery: hm}
	shared.UpdateState(&api.ActiveState{Global: &alaye.Global{
		Storage: alaye.Storage{HostsDir: hostsDir},
	}})

	r := chi.NewRouter()
	api.HostHandler(shared, r)
	return r, hm, hostsDir.Path()
}

// Finding: path traversal in the HCL create path —
// internal/operation/api/host.go:250 ("domain" query is optional), :254/:259
// (domain falls back to the HCL body, which alaye.Host.Validate does not
// validate), :295 -> internal/hub/discovery/hosts.go:860 CreateRaw, which is the
// only writer that uses filepath.Join + os.WriteFile instead of os.OpenRoot.
func TestBUG_HostCreateHCLWritesOutsideHostsDir(t *testing.T) {
	router, _, hostsDir := newHostAPI(t)

	// domain comes from the body: <hosts>/../pwn.hcl escapes the tree.
	body := "domains = [\"../pwn\"]\n\nroute \"/\" {\n  web {\n    root = \"/tmp\"\n  }\n}\n"

	req := httptest.NewRequest(http.MethodPost, "/discovery/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	escaped := filepath.Join(filepath.Dir(hostsDir), "pwn.hcl")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("BUG CONFIRMED: POST /discovery/ with a body-controlled domain wrote %q "+
			"OUTSIDE the hosts directory (HTTP %d). CreateRaw bypasses the os.OpenRoot "+
			"containment used by Create(); an authenticated API caller can therefore "+
			"overwrite any file the agbero process can write.",
			escaped, rr.Code)
	}
	t.Logf("request returned %d, body=%q", rr.Code, strings.TrimSpace(rr.Body.String()))
}

// Finding: sanitizeHostConfigs mutates live state —
// internal/operation/api/host.go:536 does a SHALLOW `clone := *v` and then writes
// `route.BasicAuth.Users = nil` through the shared Routes backing array, while
// discovery.LoadAll() (internal/hub/discovery/hosts.go:584) hands out pointers to
// the live (post-rebuild) host configs used by routing.
func TestBUG_HostListWipesLiveBasicAuthUsers(t *testing.T) {
	router, hm, hostsDir := newHostAPI(t)

	const bcryptHash = "$2y$10$abcdefghijklmnopqrstuv"
	hm.Set("auth.example", &alaye.Host{
		Domains: []string{"auth.example"},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Web:     alaye.Web{Enabled: expect.Active, Root: alaye.WebRoot("/tmp")},
			BasicAuth: alaye.BasicAuth{
				Enabled: expect.Active,
				Users:   []string{"admin:" + bcryptHash},
				Realm:   "Admin Area",
			},
		}},
	})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/discovery/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup: list returned %d: %s", rr.Code, rr.Body.String())
	}

	live := hm.Get("auth.example")
	if live == nil || len(live.Routes) == 0 {
		t.Fatalf("setup: host not registered")
	}
	if len(live.Routes[0].BasicAuth.Users) == 0 {
		t.Errorf("BUG CONFIRMED: a read-only GET /discovery/ erased basic_auth.users from the "+
			"LIVE route config (users=%v). The sanitizer writes through the shared Routes "+
			"slice handed out by discovery.LoadAll(). The next route build for this host will "+
			"reject every request, and Host.Save() will persist the loss to disk.",
			live.Routes[0].BasicAuth.Users)
	}

	// Demonstrate the persistence half of the same defect.
	if err := hm.Save("auth.example"); err != nil {
		t.Logf("note: Save returned %v", err)
	} else if raw, err := os.ReadFile(filepath.Join(hostsDir, "auth.example.hcl")); err == nil {
		if !strings.Contains(string(raw), bcryptHash) {
			t.Errorf("BUG CONFIRMED: Host.Save() persisted the mutated in-memory config — the "+
				"written host file no longer contains the basic-auth hash (%d bytes written).",
				len(raw))
		}
	}
}

// Finding: incomplete redaction — internal/operation/api/host.go:553 only nils
// BasicAuth.Users. Fields typed expect.Value redact themselves on MarshalJSON
// (expect/value.go:140), but plain strings/maps do not, so
// route.Wasm.Config, route.ForwardAuth.URL and backend.tunnel (which routinely
// embeds socks5://user:pass@host) are returned verbatim.
func TestBUG_HostListLeaksRouteSecrets(t *testing.T) {
	router, hm, _ := newHostAPI(t)

	hm.Set("secrets.example", &alaye.Host{
		Domains: []string{"secrets.example"},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Web:     alaye.Web{Enabled: expect.Active, Root: alaye.WebRoot("/tmp")},
			JWTAuth: alaye.JWTAuth{
				Enabled: expect.Active,
				Secret:  expect.Value("jwt-top-secret"),
			},
			OAuth: alaye.OAuth{
				Enabled:      expect.Active,
				Provider:     "github",
				ClientID:     "client-id",
				ClientSecret: expect.Value("oauth-client-secret"),
				CookieSecret: expect.Value("oauth-cookie-secret"),
			},
			ForwardAuth: alaye.ForwardAuth{
				Enabled:      expect.Active,
				URL:          "https://auth.internal/verify",
				AllowPrivate: true,
			},
			Wasm: alaye.Wasm{
				Enabled: expect.Active,
				Module:  "check.wasm",
				Config:  map[string]string{"api_key": "wasm-config-secret"},
			},
			Backends: alaye.Backend{
				Enabled: expect.Active,
				Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")},
				Tunnel:  "socks5://proxyuser:proxypass@127.0.0.1:9050",
			},
		}},
	})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/discovery/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup: list returned %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	leaks := []string{
		"wasm-config-secret",           // wasm.config map[string]string
		"https://auth.internal/verify", // forward_auth.url
		"proxypass",                    // backend tunnel URL credentials
	}
	for _, secret := range leaks {
		if strings.Contains(body, secret) {
			t.Errorf("BUG CONFIRMED: GET /discovery/ returned %q in its JSON response. "+
				"sanitizeRouteConfig (operation/api/host.go:553) only clears "+
				"BasicAuth.Users.", secret)
		}
	}
}

// TestBUG_HostRoundTripPreservesRedactedSecrets is the counterpart of the
// redaction test: a client that GETs a host (which returns "***" placeholders and
// drops basic_auth.users) and PUTs it back must not destroy the real credentials.
// The update path merges masked fields from the stored config
// (operation/api/host.go mergeRedactedSecrets); without it the UI/API
// GET -> edit -> PUT flow silently wipes every secret.
func TestBUG_HostRoundTripPreservesRedactedSecrets(t *testing.T) {
	router, hm, _ := newHostAPI(t)

	const bcryptHash = "$2y$10$abcdefghijklmnopqrstuv"
	hm.Set("roundtrip.example", &alaye.Host{
		Domains: []string{"roundtrip.example"},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Web:     alaye.Web{Enabled: expect.Active, Root: alaye.WebRoot("/tmp")},
			BasicAuth: alaye.BasicAuth{
				Enabled: expect.Active,
				Users:   []string{"admin:" + bcryptHash},
			},
			ForwardAuth: alaye.ForwardAuth{
				Enabled:      expect.Active,
				URL:          "https://auth.internal/verify",
				AllowPrivate: true,
			},
			Wasm: alaye.Wasm{
				Enabled: expect.Active,
				Module:  "check.wasm",
				Config:  map[string]string{"api_key": "wasm-secret"},
			},
		}},
	})

	// 1) Read the redacted document the API hands to a UI.
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/discovery/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup: list returned %d: %s", rr.Code, rr.Body.String())
	}
	var listed map[string]*alaye.Host
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("setup: decode list: %v", err)
	}
	doc := listed["roundtrip.example"]
	if doc == nil {
		t.Fatalf("setup: host missing from the list response")
	}

	// 2) Write it straight back (this is what GET -> edit -> PUT does).
	payload, err := json.Marshal(map[string]any{"domain": "roundtrip.example", "config": doc})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/discovery/roundtrip.example", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("round-trip PUT failed with %d: %s", rr.Code, rr.Body.String())
	}

	// 3) The real credentials must still be there.
	live := hm.Get("roundtrip.example")
	if live == nil || len(live.Routes) == 0 {
		t.Fatalf("host disappeared after the round-trip")
	}
	r0 := live.Routes[0]
	if len(r0.BasicAuth.Users) != 1 || !strings.Contains(r0.BasicAuth.Users[0], bcryptHash) {
		t.Errorf("BUG CONFIRMED: round-trip destroyed basic_auth.users (%v)", r0.BasicAuth.Users)
	}
	if r0.ForwardAuth.URL != "https://auth.internal/verify" {
		t.Errorf("BUG CONFIRMED: round-trip wrote %q over forward_auth.url", r0.ForwardAuth.URL)
	}
	if got := r0.Wasm.Config["api_key"]; got != "wasm-secret" {
		t.Errorf("BUG CONFIRMED: round-trip wrote %v over wasm.config", r0.Wasm.Config)
	}

	// 4) HEAD must work: the admin UI uses it to probe for an existing host
	// (chi does not map HEAD onto GET automatically, so it returned 405).
	headReq := httptest.NewRequest(http.MethodHead, "/discovery/roundtrip.example", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, headReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD /discovery/{domain} must return 200 for an existing host, got %d "+
			"(the admin UI's checkHostExists relies on it)", rr.Code)
	}
}
