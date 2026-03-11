package tlss

import (
	"os"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
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
		global.Storage.CertsDir = tmpDir
	}
	if global.Storage.DataDir == "" {
		global.Storage.DataDir = tmpDir
	}
	if global.Gossip.SecretKey == "" {
		global.Gossip.SecretKey = "test-secret-1234567890123456"
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global)

	// CRITICAL: Enable mock mode for the local installer to prevent system CA installation
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}

	// Also set environment variable to indicate test mode
	os.Setenv("AGBERO_TEST_MODE", "1")

	return mgr, tmpDir
}

// SetupTestLocal creates a Local instance with mock mode enabled
func SetupTestLocal(t *testing.T, tmpDir string) *Local {
	t.Helper()
	logger := testLogger
	ci := NewLocal(logger)
	ci.CertDir = woos.NewFolder(tmpDir)
	ci.SetMockMode(true)
	return ci
}
