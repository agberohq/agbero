package tlss

import (
	"crypto/tls"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/ll"
)

func setupManager(t *testing.T) (*Manager, string) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir, DataDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "secret-12345678"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		t.Error("Expected TLS 1.2 minimum")
	}
}
