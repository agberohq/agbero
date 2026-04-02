package tlss

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/olekukonko/ll"
)

func setupManager(t *testing.T) (*Manager, string) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
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
