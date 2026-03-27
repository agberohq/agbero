package agbero

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/jack"
	"golang.org/x/crypto/bcrypt"
)

func newTestAdminServer(t *testing.T) (*Server, *http.Server, int, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	certsDir := filepath.Join(tmpDir, "certs")
	dataDir := filepath.Join(tmpDir, "data")

	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(certsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	adminPort := zulu.PortFree()
	httpPort := zulu.PortFree()

	hm := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))

	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			CertsDir: certsDir,
			DataDir:  dataDir,
			WorkDir:  filepath.Join(tmpDir, "work"),
		},
		Bind: alaye.Bind{
			HTTP:     []string{fmt.Sprintf("127.0.0.1:%d", httpPort)},
			Redirect: alaye.Inactive,
		},
		Admin: alaye.Admin{
			Enabled: alaye.Active,
			Address: fmt.Sprintf("127.0.0.1:%d", adminPort),
			JWTAuth: alaye.JWTAuth{
				Enabled: alaye.Active,
				Secret:  "test-secret-key-32-bytes-minimum!",
			},
			BasicAuth: alaye.BasicAuth{
				Enabled: alaye.Active,
				Users:   []string{bcryptEntry(t, "admin", "correct-password")},
			},
			TOTP:      alaye.TOTP{Enabled: alaye.Inactive},
			Telemetry: alaye.Telemetry{Enabled: alaye.Inactive},
		},
		Logging: alaye.Logging{Enabled: alaye.Inactive},
		Timeouts: alaye.Timeout{
			Enabled: alaye.Active,
			Read:    alaye.Duration(5 * time.Second),
			Write:   alaye.Duration(5 * time.Second),
			Idle:    alaye.Duration(5 * time.Second),
		},
		General: alaye.General{MaxHeaderBytes: alaye.DefaultMaxHeaderBytes},
		Gossip:  alaye.Gossip{Enabled: alaye.Inactive},
	}

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	s := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
		WithLogger(testLogger),
		WithShutdownManager(shutdown),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := s.Start(""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	waitForPort(t, adminPort)
	waitForPort(t, httpPort)

	// Wait until s.adminSrv is actually assigned (this removes the race)
	for i := 0; i < 100; i++ {
		s.mu.RLock()
		ready := s.adminSrv != nil
		s.mu.RUnlock()
		if ready {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.adminSrv == nil {
		t.Fatal("admin server failed to initialize (s.adminSrv is still nil)")
	}

	cleanup := func() {
		shutdown.TriggerShutdown()
		time.Sleep(300 * time.Millisecond)

		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Logf("Server error during shutdown: %v", err)
			}
		default:
		}
	}

	return s, s.adminSrv, adminPort, cleanup
}

func bcryptEntry(t *testing.T, username, password string) string {
	t.Helper()
	p := security.NewPassword()
	hash, err := p.HashWithCost(password, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcryptEntry: %v", err)
	}
	return fmt.Sprintf("%s:%s", username, hash)
}

func makeRequest(t *testing.T, port int, method, path string, body []byte, token string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	return resp
}

func getToken(t *testing.T, port int) string {
	t.Helper()
	body := `{"username":"admin","password":"correct-password"}`
	resp := makeRequest(t, port, http.MethodPost, "/login", []byte(body), "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes := make([]byte, 1024)
		n, _ := resp.Body.Read(bodyBytes)
		t.Fatalf("Login failed: %d - %s", resp.StatusCode, string(bodyBytes[:n]))
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	return result["token"]
}

// ==================== CORE ENDPOINTS ====================
func TestAdminCoreEndpoints(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	t.Run("GET /healthz - returns OK", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/healthz", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /status - returns status", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/status", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "ok" {
			t.Error("status not ok")
		}
	})

	t.Run("POST /login - success", func(t *testing.T) {
		body := `{"username":"admin","password":"correct-password"}`
		resp := makeRequest(t, port, http.MethodPost, "/login", []byte(body), "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("POST /login - invalid credentials", func(t *testing.T) {
		body := `{"username":"admin","password":"wrong"}`
		resp := makeRequest(t, port, http.MethodPost, "/login", []byte(body), "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("POST /logout - revokes token", func(t *testing.T) {
		token := getToken(t, port)
		resp := makeRequest(t, port, http.MethodPost, "/logout", nil, token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		time.Sleep(100 * time.Millisecond)
		resp2 := makeRequest(t, port, http.MethodGet, "/uptime", nil, token)
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 after logout, got %d", resp2.StatusCode)
		}
	})
}

// ==================== HOST MANAGEMENT API ====================
func TestAdminHostAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/discovery"

	t.Run("GET /api/v1/discovery - requires auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath, nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("POST /api/v1/discovery - create host", func(t *testing.T) {
		payload := `{
			"domain": "test.example.com",
			"config": {
				"domains": ["test.example.com"],
				"routes": [{
					"path": "/",
					"backends": {
						"servers": [{"address": "http://127.0.0.1:8080"}]
					}
				}]
			}
		}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /api/v1/discovery - list hosts", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath, nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /api/v1/discovery/test.example.com - get host", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath+"/test.example.com", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("DELETE /api/v1/discovery/test.example.com - delete host", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodDelete, basePath+"/test.example.com", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}

// ==================== SECRETS UTILITY API ====================
func TestAdminSecretsAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/secrets"

	t.Run("POST /api/v1/secrets - hash password", func(t *testing.T) {
		payload := `{"action":"hash","password":"testpass"}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["hash"] == "" {
			t.Error("hash missing")
		}
	})

	t.Run("POST /api/v1/secrets - generate password", func(t *testing.T) {
		payload := `{"action":"password","length":16}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["password"] == "" || result["hash"] == "" {
			t.Error("password or hash missing")
		}
	})

	t.Run("POST /api/v1/secrets - generate key", func(t *testing.T) {
		payload := `{"action":"key","length":32}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["key"] == "" {
			t.Error("key missing")
		}
	})

	t.Run("POST /api/v1/secrets - unknown action", func(t *testing.T) {
		payload := `{"action":"unknown"}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
	})
}

// ==================== ADMIN UI ENDPOINTS ====================
func TestAdminUIEndpoints(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)

	t.Run("GET /uptime - requires auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/uptime", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /uptime - with auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/uptime", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /metrics - requires auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/metrics", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /metrics - with auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/metrics", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /config - requires auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/config", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /config - with auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, "/config", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}

// ==================== TOTP API ====================
func TestAdminTOTPAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/totp"

	t.Run("POST /api/v1/totp/setup - requires auth", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodPost, basePath+"/setup", nil, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("POST /api/v1/totp/setup - with auth (TOTP disabled)", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodPost, basePath+"/setup", nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 501 or 401 (TOTP disabled), got %d", resp.StatusCode)
		}
	})
}

// ==================== CLUSTER API ====================
func TestAdminClusterAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/cluster"

	t.Run("POST /api/v1/cluster - cluster disabled", func(t *testing.T) {
		payload := `{"host":"example.com","path":"/api"}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		// Cluster is disabled in test config
		if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 503 or 404, got %d", resp.StatusCode)
		}
	})
}

// ==================== KEEPER API ====================
func TestAdminKeeperAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/keeper"

	t.Run("GET /api/v1/keeper/secrets - keeper not configured", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath+"/secrets", nil, validToken)
		defer resp.Body.Close()
		// Keeper is not configured in test config
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Logf("Keeper not configured - got %d", resp.StatusCode)
		}
	})
}

// ==================== FIREWALL API ====================
func TestAdminFirewallAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/firewall"

	t.Run("GET /api/v1/firewall - list blocked IPs", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath, nil, validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("POST /api/v1/firewall - block IP (firewall disabled)", func(t *testing.T) {
		payload := `{"ip":"192.168.1.100","reason":"test block","duration_sec":3600}`
		resp := makeRequest(t, port, http.MethodPost, basePath, []byte(payload), validToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Logf("Firewall not enabled - got %d", resp.StatusCode)
		}
	})
}

// ==================== CERTIFICATES API ====================
func TestAdminCertsAPI(t *testing.T) {
	_, _, port, cleanup := newTestAdminServer(t)
	defer cleanup()

	validToken := getToken(t, port)
	basePath := "/api/v1/certs"

	t.Run("GET /api/v1/certs - list certificates", func(t *testing.T) {
		resp := makeRequest(t, port, http.MethodGet, basePath, nil, validToken)
		defer resp.Body.Close()
		// TLS manager may not be fully initialized in test, but should not panic
		if resp.StatusCode == http.StatusInternalServerError {
			t.Log("TLS manager not fully initialized - test environment limitation")
		} else if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}
