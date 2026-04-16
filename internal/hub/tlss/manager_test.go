package tlss

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("tlss").Disable()
)

// SetupTestManager creates a Manager with mock mode enabled for testing
func SetupTestManager(t *testing.T, global *alaye.Global) (*Manager, string) {
	t.Helper()

	tmpDir := t.TempDir()

	// Set default values if not provided
	if global.Storage.CertsDir == "" {
		global.Storage.CertsDir = expect.NewFolder(tmpDir)
	}
	if global.Storage.DataDir == "" {
		global.Storage.DataDir = expect.NewFolder(tmpDir)
	}
	if global.Gossip.SecretKey == "" {
		global.Gossip.SecretKey = "test-secret-1234567890123456"
	}

	hm := discovery.NewHost(expect.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)

	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}

	// Also set environment variable to indicate test mode
	os.Setenv("AGBERO_TEST_MODE", "1")

	return mgr, tmpDir
}

func setupManager(t *testing.T) (*Manager, string) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
			DataDir:  expect.NewFolder(filepath.Join(tmpDir, "data")),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(expect.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global, nil)
	return mgr, tmpDir
}

func TestManager_GetConfigForClient(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()
	cfg, err := mgr.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient failed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Error("expected TLS 1.2 minimum")
	}
}
