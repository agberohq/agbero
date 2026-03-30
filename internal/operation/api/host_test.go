package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("").Disable()

// validBackendPayload builds a minimal JSON host payload with a backend route.
func validBackendPayload(domain, backendAddr string) []byte {
	body := fmt.Sprintf(`{
		"domain": %q,
		"config": {
			"domains": [%q],
			"routes": [{
				"path": "/",
				"backends": {
					"servers": [{"address": %q}]
				}
			}]
		}
	}`, domain, domain, backendAddr)
	return []byte(body)
}

// validWebPayload builds a minimal JSON host payload with a web route.
// root is required — omitting it causes ErrRouteNoBackendOrWeb.
func validWebPayload(domain, root string) []byte {
	body := fmt.Sprintf(`{
		"domain": %q,
		"config": {
			"domains": [%q],
			"routes": [{
				"path": "/",
				"web": {
					"enabled": "on",
					"root": %q,
					"spa": true,
					"listing": true
				}
			}]
		}
	}`, domain, domain, root)
	return []byte(body)
}

// setupTestHost creates a temp hosts dir, a discovery instance, and a Shared
// wired for host handler tests. Returns cleanup to defer.
func setupTestHost(t *testing.T) (*discovery.Host, string, *Shared, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatalf("failed to create hosts dir: %v", err)
	}

	hosts := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))
	global := &alaye.Global{
		Storage: alaye.Storage{HostsDir: hostsDir},
	}
	shared := &Shared{
		Logger:    testLogger,
		Discovery: hosts,
	}
	shared.UpdateState(&ActiveState{Global: global})

	cleanup := func() {
		hosts.Close()
		os.RemoveAll(tmpDir)
	}
	return hosts, hostsDir, shared, cleanup
}

func TestHostHandler_List(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	hostFile := filepath.Join(hostsDir, "test.example.com.hcl")
	if err := os.WriteFile(hostFile, []byte(`domains = ["test.example.com"]
route "/" {
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := shared.Discovery.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]*alaye.Host
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to decode response: %v", err)
	}
	if len(resp) == 0 {
		t.Error("expected hosts in response, got none")
	}
}

func TestHostHandler_Get(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	hostFile := filepath.Join(hostsDir, "get-test.example.com.hcl")
	if err := os.WriteFile(hostFile, []byte(`domains = ["get-test.example.com"]
route "/" {
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := shared.Discovery.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/discovery/get-test.example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp alaye.Host
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to decode response: %v", err)
	}
	if len(resp.Domains) == 0 || resp.Domains[0] != "get-test.example.com" {
		t.Errorf("expected domain get-test.example.com, got %v", resp.Domains)
	}
}

func TestHostHandler_Create_JSON_Backend(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/discovery",
		bytes.NewReader(validBackendPayload("create-backend.example.com", backend.URL)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("create-backend.example.com") == nil {
		t.Error("host not found after JSON backend create")
	}
}

// TestHostHandler_Create_JSON_Web_MissingRoot ensures the validator correctly
// rejects a web route that omits the required root attribute.
func TestHostHandler_Create_JSON_Web_MissingRoot(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	r := chi.NewRouter()
	HostHandler(shared, r)

	// web route without root — must be rejected
	payload := []byte(`{
		"domain": "noweb.example.com",
		"config": {
			"domains": ["noweb.example.com"],
			"routes": [{
				"path": "/",
				"web": { "enabled": "on", "spa": true, "listing": true }
			}]
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/discovery", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing web root, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestHostHandler_Create_JSON_Web_WithRoot(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/discovery",
		bytes.NewReader(validWebPayload("web.example.com", ".")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("web.example.com") == nil {
		t.Error("host not found after JSON web create")
	}
}

func TestHostHandler_Create_HCL_Backend(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	r := chi.NewRouter()
	HostHandler(shared, r)

	rawHCL := `
# backend service config
domains = ["hcl-backend.example.com"]

# the route information
route "/" {
  backend {
	server { address = "http://127.0.0.1:9000" }
  }
}
`
	req := httptest.NewRequest(http.MethodPost, "/discovery?domain=hcl-backend.example.com",
		bytes.NewReader([]byte(rawHCL)))
	req.Header.Set("Content-Type", "application/hcl")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("hcl-backend.example.com") == nil {
		t.Error("host not found after HCL create")
	}

	// Verify comments are preserved on disk
	files, _ := os.ReadDir(hostsDir)
	found := false
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".hcl" {
			data, _ := os.ReadFile(filepath.Join(hostsDir, f.Name()))
			if bytes.Contains(data, []byte("# backend service config")) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("HCL comment not preserved on disk after create")
	}
}

func TestHostHandler_Create_HCL_Web(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	r := chi.NewRouter()
	HostHandler(shared, r)

	rawHCL := `# static site
domains = ["hcl-web.example.com"]

route "/" {
  web {
    enabled = "on"
    root    = "."
    spa     = true
    listing = true
  }
}
`
	req := httptest.NewRequest(http.MethodPost, "/discovery?domain=hcl-web.example.com",
		bytes.NewReader([]byte(rawHCL)))
	req.Header.Set("Content-Type", "application/hcl")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("hcl-web.example.com") == nil {
		t.Error("host not found after HCL web create")
	}
}

func TestHostHandler_Delete(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	hostFile := filepath.Join(hostsDir, "delete-test.example.com.hcl")
	if err := os.WriteFile(hostFile, []byte(`domains = ["delete-test.example.com"]
route "/" {
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := shared.Discovery.ReloadFull(); err != nil {
		t.Fatal(err)
	}
	if shared.Discovery.Get("delete-test.example.com") == nil {
		t.Fatal("host not loaded before delete test")
	}

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/discovery/delete-test.example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("delete-test.example.com") != nil {
		t.Error("host still present after DELETE")
	}
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Error("host file still on disk after DELETE")
	}
}

func TestHostHandler_ProtectedHost(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	shared.Discovery.Set("protected.example.com", &alaye.Host{
		Protected: alaye.Active,
		Domains:   []string{"protected.example.com"},
		Routes: []alaye.Route{{
			Path:     "/",
			Backends: alaye.Backend{Servers: []alaye.Server{{Address: "http://127.0.0.1:8080"}}},
		}},
	})

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/discovery/protected.example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for protected host, got %d", w.Code)
	}
}
