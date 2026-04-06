package tlss

import (
	"os"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("tlss").Enable()
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
