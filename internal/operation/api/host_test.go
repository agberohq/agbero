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

func validHostPayload(domain, backendAddr string) []byte {
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

func setupTestHost(t *testing.T) (*discovery.Host, string, *Shared, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatalf("Failed to create hosts dir: %v", err)
	}

	// Discovery is created and managed directly, NOT in ActiveState
	hosts := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))

	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: hostsDir,
		},
	}

	shared := &Shared{
		Logger:    testLogger,
		Discovery: hosts, // Discovery is a direct field
	}

	// Only Global is in ActiveState (hot-reloadable config)
	shared.UpdateState(&ActiveState{
		Global: global,
		// Firewall and TLSS are nil in this test
	})

	cleanup := func() {
		hosts.Close()
		os.RemoveAll(tmpDir)
	}

	return hosts, hostsDir, shared, cleanup
}

func TestHostHandler_List(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	// Create a test host file
	hostFile := filepath.Join(hostsDir, "test.example.com.hcl")
	if err := os.WriteFile(hostFile, []byte(`domains = ["test.example.com"]
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
`), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	// Discovery has its own reload mechanism
	if err := shared.Discovery.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]*alaye.Host
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if len(resp) == 0 {
		t.Error("Expected hosts in response")
	}
}

func TestHostHandler_Get(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	// Create a test host file
	hostFile := filepath.Join(hostsDir, "get-test.example.com.hcl")
	hostContent := `domains = ["get-test.example.com"]
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
`
	if err := os.WriteFile(hostFile, []byte(hostContent), woos.FilePerm); err != nil {
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
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp alaye.Host
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if len(resp.Domains) == 0 || resp.Domains[0] != "get-test.example.com" {
		t.Errorf("Expected domain get-test.example.com, got %v", resp.Domains)
	}
}

func TestHostHandler_Create(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	r := chi.NewRouter()
	HostHandler(shared, r)

	payload := validHostPayload("create-test.example.com", backend.URL)
	req := httptest.NewRequest(http.MethodPost, "/discovery", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	// Discovery is accessed directly, NOT through State()
	created := shared.Discovery.Get("create-test.example.com")
	if created == nil {
		t.Error("Host not found after creation")
	}
}

func TestHostHandler_Delete(t *testing.T) {
	_, hostsDir, shared, cleanup := setupTestHost(t)
	defer cleanup()

	// Create a host to delete
	hostFile := filepath.Join(hostsDir, "delete-test.example.com.hcl")
	hostContent := `domains = ["delete-test.example.com"]
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
`
	if err := os.WriteFile(hostFile, []byte(hostContent), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	if err := shared.Discovery.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	if shared.Discovery.Get("delete-test.example.com") == nil {
		t.Fatal("Host not loaded before delete test")
	}

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/discovery/delete-test.example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if shared.Discovery.Get("delete-test.example.com") != nil {
		t.Error("Host still present after DELETE")
	}
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Error("Host file still on disk after DELETE")
	}
}

func TestHostHandler_ProtectedHost(t *testing.T) {
	_, _, shared, cleanup := setupTestHost(t)
	defer cleanup()

	protectedHost := &alaye.Host{
		Protected: alaye.Active,
		Domains:   []string{"protected.example.com"},
		Routes: []alaye.Route{{
			Path: "/",
			Backends: alaye.Backend{
				Servers: []alaye.Server{{Address: "http://127.0.0.1:8080"}},
			},
		}},
	}
	// Discovery is accessed directly
	shared.Discovery.Set("protected.example.com", protectedHost)

	r := chi.NewRouter()
	HostHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/discovery/protected.example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}
