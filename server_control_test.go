package agbero

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/control"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/olekukonko/jack"
)

func TestServer_ControlSocketRevokesToken(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	hostsDir := expect.NewFolder(filepath.Join(tmpDir, "hosts"))
	if err := hostsDir.Make(false); err != nil {
		t.Fatal(err)
	}
	if err := dataDir.Make(true); err != nil {
		t.Fatal(err)
	}
	global := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{"127.0.0.1:0"}},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  dataDir,
			CertsDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
		},
		Timeouts: alaye.Timeout{
			Enabled: expect.Active, Read: expect.Duration(time.Second),
			Write: expect.Duration(time.Second), Idle: expect.Duration(5 * time.Second),
		},
		General:  alaye.General{MaxHeaderBytes: 1 << 20},
		Security: alaye.Security{Keeper: alaye.Keeper{Enabled: expect.Inactive}},
	}
	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(time.Second))
	path := control.SocketPath(dataDir.Path())
	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(testLogger),
		WithShutdownManager(shutdown),
		WithControlSocket(path),
	)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start("") }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := control.DialRetry(ctx, path)
	if err != nil {
		shutdown.TriggerShutdown()
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(ctx, "revoke.add", map[string]any{
		"jti": "e2e-control-jti", "service": "test", "expires_at": time.Now().Add(time.Hour),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if s.revokeStore == nil || !s.revokeStore.IsRevoked("e2e-control-jti") {
		t.Fatal("daemon did not observe revocation through control socket")
	}
	shutdown.TriggerShutdown()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}
