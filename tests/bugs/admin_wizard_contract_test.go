package bugs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

// wizardPayload is the REAL output of
// internal/operation/admin/js/host-builder.js `buildHostConfig()` for a draft
// with Let's Encrypt TLS, a proxy route, OAuth, a proxy fallback and a body-size
// limit. Regenerate with:
//
//	node --input-type=module -e "import {buildHostConfig} from '…/host-builder.js';
//	console.log(JSON.stringify(buildHostConfig({…}), null, 2))"
//
// It is checked with DisallowUnknownFields, because encoding/json silently drops
// unknown keys at runtime — `o_auth` (instead of `oauth`) and `letsencrypt`
// (instead of `lets_encrypt`) both shipped that way, and the wizard reported
// success while the blocks vanished from the saved host.
const wizardPayload = `{
  "domains": ["app.example.com"],
  "tls": {
    "mode": "letsencrypt",
    "lets_encrypt": { "enabled": "on", "email": "ops@example.com", "staging": "on" }
  },
  "compression": true,
  "limits": { "max_body_size": 1048576 },
  "routes": [{
    "enabled": "on",
    "path": "/api",
    "backends": {
      "enabled": "on",
      "strategy": "round_robin",
      "servers": [{ "address": "http://10.0.0.5:8080", "weight": 2 }]
    },
    "fallback": {
      "enabled": "on", "type": "proxy",
      "proxy_url": "https://fallback.internal:8081", "cache_ttl": 30
    },
    "oauth": {
      "enabled": "on", "provider": "github", "client_id": "cid",
      "client_secret": "csecret", "redirect_url": "https://app.example.com/cb",
      "cookie_secret": "cookie-secret-16plus"
    }
  }]
}`

// TestADMIN_WizardPayloadConformsToSchema guards the wizard → API contract.
func TestADMIN_WizardPayloadConformsToSchema(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(wizardPayload))
	dec.DisallowUnknownFields()

	var host alaye.Host
	if err := dec.Decode(&host); err != nil {
		t.Fatalf("wizard payload does not match alaye.Host: %v\n"+
			"A renamed JSON tag on either side is dropped silently at runtime — check "+
			"the builder against internal/core/alaye/*.go", err)
	}

	// Decoding without error is not enough: the values must land in real fields.
	if got := host.TLS.LetsEncrypt.Email; got != "ops@example.com" {
		t.Errorf("tls.lets_encrypt.email lost (got %q) — builder must use the json tag `lets_encrypt`", got)
	}
	if !host.TLS.LetsEncrypt.Staging.Active() {
		t.Error("tls.lets_encrypt.staging lost — staging requests would hit production ACME")
	}
	if host.Limits.MaxBodySize != 1048576 {
		t.Errorf("limits.max_body_size lost (got %d) — the wizard used to send max_header_bytes", host.Limits.MaxBodySize)
	}
	if !host.Compression {
		t.Error("host compression flag lost")
	}

	if len(host.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(host.Routes))
	}
	r := host.Routes[0]

	if !r.OAuth.Enabled.Active() || r.OAuth.Provider != "github" || r.OAuth.ClientID != "cid" {
		t.Errorf("route.oauth lost (%+v) — builder must use the json tag `oauth`, not `o_auth`", r.OAuth)
	}
	if r.Fallback.Type != "proxy" || r.Fallback.ProxyURL != "https://fallback.internal:8081" {
		t.Errorf("route.fallback not decoded as proxy (%+v) — `type` is required by Fallback.Validate", r.Fallback)
	}
	if r.Fallback.CacheTTL != 30 {
		t.Errorf("fallback cache_ttl lost (got %d)", r.Fallback.CacheTTL)
	}
	if len(r.Backends.Servers) != 1 || r.Backends.Servers[0].Weight != 2 {
		t.Errorf("backend servers lost: %+v", r.Backends.Servers)
	}

	// And the result must pass the same validation the create endpoint runs.
	woos.DefaultHost(&host)
	if err := host.Validate(); err != nil {
		t.Fatalf("wizard payload does not validate: %v", err)
	}
}

// wizardHCL is what `buildHostHCL()` renders for the same draft — the client-side
// fallback shown when the preview endpoint is unavailable, and (after editing) a
// valid submit body. It is parsed with the real HCL decoder so the renderer can't
// drift from the schema either.
const wizardHCL = `domains = ["app.example.com"]

limits {
  max_body_size = 1048576
}

tls {
  mode = "letsencrypt"

  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
    staging = "on"
  }
}

route "/api" {
  backend {
    server {
      address = "http://10.0.0.5:8080"
      weight  = 2
    }
  }

  fallback {
    enabled = "on"
    type         = "proxy"
    proxy_url    = "https://fallback.internal:8081"
  }

  o_auth {
    enabled       = "on"
    provider      = "github"
    client_id     = "cid"
    client_secret = "cs"
    redirect_url  = "https://app.example.com/cb"
    cookie_secret = "cookie-secret-16plus"
  }
}
`

// TestADMIN_WizardHCLRoundTrips parses the renderer's own output, so the HCL
// preview/fallback path is held to the same standard as the JSON payload.
func TestADMIN_WizardHCLRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.example.com.hcl")
	if err := os.WriteFile(path, []byte(wizardHCL), 0o600); err != nil {
		t.Fatalf("write temp hcl: %v", err)
	}

	host, err := parser.ParseHostConfig(path)
	if err != nil {
		t.Fatalf("client-rendered HCL does not parse: %v", err)
	}

	if host.TLS.LetsEncrypt.Email != "ops@example.com" {
		t.Errorf("lets_encrypt.email lost in HCL round-trip: %q", host.TLS.LetsEncrypt.Email)
	}
	if host.Limits.MaxBodySize != 1048576 {
		t.Errorf("limits.max_body_size lost in HCL round-trip: %d", host.Limits.MaxBodySize)
	}
	if len(host.Routes) != 1 || len(host.Routes[0].Backends.Servers) != 1 {
		t.Fatalf("route/backend lost in HCL round-trip: %+v", host.Routes)
	}
	if !host.Routes[0].OAuth.Enabled.Active() {
		t.Fatalf("o_auth block lost in HCL round-trip")
	}
	if host.Routes[0].Fallback.Type != "proxy" {
		t.Fatalf("fallback type lost in HCL round-trip: %+v", host.Routes[0].Fallback)
	}
}

// wizardTCPHCL / wizardServerlessHCL are the renderer's output for TCP-proxy and
// serverless drafts. Both used the wrong HCL block names (`server` instead of
// `backend`, `worker` instead of `work`) and decoded to empty configs.
const wizardTCPHCL = `domains = ["tcp.example"]

proxy "primary" {
  enabled  = "on"
  listen   = ":5432"
  strategy = "least_conn"
  backend {
    address = "10.0.0.5:5432"
    weight  = 3
  }
  backend { address = "10.0.0.6:5432" }
}
`

const wizardServerlessHCL = `domains = ["sl.example"]

route "/fn" {
  serverless {
    work "render" {
      enabled  = "on"
      command  = ["node", "index.js"]
      landlock = "on"
    }

    replay "stripe" {
      enabled = "on"
      url            = "https://api.stripe.com/v1"
    }
  }
}
`

// TestADMIN_WizardHCLRoundTripsTCPAndServerless covers the other two host types.
func TestADMIN_WizardHCLRoundTripsTCPAndServerless(t *testing.T) {
	parse := func(name, body string) *alaye.Host {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		h, err := parser.ParseHostConfig(path)
		if err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		return h
	}

	tcp := parse("tcp.example.hcl", wizardTCPHCL)
	if len(tcp.Proxies) != 1 {
		t.Fatalf("decoded %d proxy blocks, want 1", len(tcp.Proxies))
	}
	if p := tcp.Proxies[0]; p.Name != "primary" || len(p.Backends) != 2 || p.Backends[0].Weight != 3 {
		t.Fatalf("proxy block lost data: %+v", p)
	}

	sl := parse("sl.example.hcl", wizardServerlessHCL)
	if len(sl.Routes) != 1 {
		t.Fatalf("decoded %d routes, want 1", len(sl.Routes))
	}
	srv := sl.Routes[0].Serverless
	if len(srv.Workers) != 1 || srv.Workers[0].Name != "render" || len(srv.Workers[0].Command) != 2 {
		t.Fatalf("work block lost data: %+v", srv.Workers)
	}
	if len(srv.Replay) != 1 || srv.Replay[0].Name != "stripe" {
		t.Fatalf("replay block lost data: %+v", srv.Replay)
	}
}

// TestADMIN_CreateHostHCLWithoutContentType is the regression for the oja `raw`
// bug: the wizard posts HCL with no Content-Type (oja used to strip the one the
// caller set), and the handler answered "Invalid JSON payload" because an absent
// header was treated as JSON. The server now sniffs the body.
func TestADMIN_CreateHostHCLWithoutContentType(t *testing.T) {
	router, hm, _ := newHostAPI(t)

	hcl := "domains = [\"hclexample.test\"]\n\nroute \"/\" {\n  web {\n    root = \"/tmp\"\n  }\n}\n"

	req := httptest.NewRequest(http.MethodPost, "/discovery/", strings.NewReader(hcl))
	req.Header.Del("Content-Type") // what oja's raw mode actually sent
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("HCL create without Content-Type must be accepted, got %d: %s", rr.Code, rr.Body.String())
	}
	if hm.Get("hclexample.test") == nil {
		t.Fatalf("host was not registered — the HCL body was not parsed")
	}

	// The response shape the admin UI uses to decide success.
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out["status"] != "ok" {
		t.Fatalf("create must answer {\"status\":\"ok\"} (UI success contract), got %q", rr.Body.String())
	}
}

// TestADMIN_CreateHostJSONKeepsOAuth guards the `oauth` JSON key end-to-end: the
// wizard used to send `o_auth` (the HCL name) and the block was dropped, leaving
// the route unauthenticated.
func TestADMIN_CreateHostJSONKeepsOAuth(t *testing.T) {
	router, hm, _ := newHostAPI(t)

	payload := `{"domain":"oauth.example","config":{
	  "domains":["oauth.example"],
	  "routes":[{
	    "enabled":"on","path":"/",
	    "web":{"enabled":"on","root":"/tmp"},
	    "oauth":{"enabled":"on","provider":"github","client_id":"cid",
	             "client_secret":"secret","redirect_url":"https://oauth.example/cb",
	             "cookie_secret":"cookie-secret-16plus"}
	  }]}}`

	req := httptest.NewRequest(http.MethodPost, "/discovery/", bytes.NewReader([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("JSON create failed: %d %s", rr.Code, rr.Body.String())
	}

	live := hm.Get("oauth.example")
	if live == nil || len(live.Routes) == 0 {
		t.Fatalf("host not registered")
	}
	if !live.Routes[0].OAuth.Enabled.Active() || live.Routes[0].OAuth.Provider != "github" {
		t.Fatalf("BUG CONFIRMED: OAuth was dropped — route would be unauthenticated (%+v)",
			live.Routes[0].OAuth)
	}
}

// TestADMIN_EndToEndCreateHCLNoContentType runs the wizard's real request against
// a live admin server: authenticated POST of raw HCL with NO Content-Type, then
// verifies the host shows up in the discovery listing.
func TestADMIN_EndToEndCreateHCLNoContentType(t *testing.T) {
	ts := startTestServer(t, serverOpts{admin: true})

	loginStatus, loginBody := postJSON(t, ts.adminURL("/login"), map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	}, "")
	if loginStatus != http.StatusOK {
		t.Fatalf("setup: login failed (%d): %s", loginStatus, loginBody)
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(loginBody), &login); err != nil || login.Token == "" {
		t.Fatalf("setup: decode login token: %v (%s)", err, loginBody)
	}

	hcl := "domains = [\"e2e.example\"]\n\nroute \"/\" {\n  backend {\n    server {\n      address = \"http://127.0.0.1:9\"\n    }\n  }\n}\n"

	req, err := http.NewRequest(http.MethodPost, ts.adminURL("/api/v1/discovery/"), strings.NewReader(hcl))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+login.Token)
	// Deliberately no Content-Type: this is what oja's raw mode used to send.
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("e2e HCL create failed: %d %s", resp.StatusCode, string(body))
	}

	// The host must now be listed.
	listResp := makeRequestWithToken(t, ts.adminURL("/api/v1/discovery/"), login.Token)
	if !strings.Contains(listResp, "e2e.example") {
		t.Fatalf("created host missing from discovery listing: %s", listResp)
	}
}

// makeRequestWithToken performs an authenticated GET and returns the body.
func makeRequestWithToken(t *testing.T, url, token string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", url, resp.StatusCode, string(b))
	}
	return string(b)
}

// UI relies on: creating an existing domain overwrites by default, and only
// ?overwrite=false answers 409.
func TestADMIN_CreateHostOverwriteSemantics(t *testing.T) {
	router, _, _ := newHostAPI(t)

	hcl := "domains = [\"dup.example\"]\n\nroute \"/\" {\n  web {\n    root = \"/tmp\"\n  }\n}\n"
	post := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(hcl))
		req.Header.Set("Content-Type", "text/plain")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := post("/discovery/"); code != http.StatusOK {
		t.Fatalf("first create: got %d", code)
	}
	if code := post("/discovery/?overwrite=false"); code != http.StatusConflict {
		t.Fatalf("second create with overwrite=false must answer 409, got %d", code)
	}
	if code := post("/discovery/"); code != http.StatusOK {
		t.Fatalf("create without overwrite must replace (documented default), got %d", code)
	}
}
