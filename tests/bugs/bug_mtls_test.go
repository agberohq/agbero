package bugs

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/handlers"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/pkg/ja3"
)

// Finding: mTLS disabled — internal/handlers/manager.go:314 (HTTP) and :347 (H3)
// both do `localCfg.GetConfigForClient = nil`, which discards the only code path
// that maps tls.client_auth / client_cas onto the listener config
// (internal/hub/tlss/manager.go:523). The same nil also drops the ja3.InjectHello
// wrapper installed at internal/handlers/manager.go:143.
func TestBUG_MTLSClientAuthNotEnforced(t *testing.T) {
	tmp := t.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmp, "hosts"))
	if err := hostsDir.Init(expect.DirPerm); err != nil {
		t.Fatalf("mkdir hosts: %v", err)
	}

	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("prime host manager: %v", err)
	}
	hm.Set("mtls.example", &alaye.Host{
		Domains: []string{"mtls.example"},
		TLS: alaye.TLS{
			Enabled:    expect.Active,
			Mode:       def.ModeLocalAuto,
			ClientAuth: def.TlsRequireAndVerify,
		},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Backends: alaye.Backend{
				Enabled: expect.Active,
				Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:8080")},
			},
		}},
	})

	hm.Set("plain.example", &alaye.Host{
		Domains: []string{"plain.example"},
		TLS:     alaye.TLS{Enabled: expect.Active, Mode: def.ModeLocalAuto},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Backends: alaye.Backend{
				Enabled: expect.Active,
				Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:8080")},
			},
		}},
	})

	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			CertsDir: expect.NewFolder(filepath.Join(tmp, "certs")),
			DataDir:  expect.NewFolder(filepath.Join(tmp, "data")),
			WorkDir:  expect.NewFolder(filepath.Join(tmp, "work")),
		},
		Bind: alaye.Bind{HTTPS: []string{"127.0.0.1:0"}},
	}

	tlsMgr := tlss.NewManager(testLogger, hm, global, nil)
	t.Cleanup(tlsMgr.Close)

	// Precondition: the TLS manager itself DOES request a client certificate.
	direct, err := tlsMgr.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "mtls.example"})
	if err != nil {
		t.Fatalf("precondition: GetConfigForClient: %v", err)
	}
	if direct.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("precondition failed: tlss.Manager.GetConfigForClient returned ClientAuth=%v, want RequireAndVerifyClientCert",
			direct.ClientAuth)
	}

	res := resource.New(resource.WithLogger(testLogger))
	t.Cleanup(res.Close)

	tm, err := handlers.NewManager(handlers.ManagerConfig{
		Global:      global,
		HostManager: hm,
		Resource:    res,
		TLSManager:  tlsMgr,
	})
	if err != nil {
		t.Fatalf("handlers.NewManager: %v", err)
	}
	t.Cleanup(tm.Close)

	var tlsListener *handlers.HTTPListener
	for _, l := range tm.BuildListeners() {
		if hl, ok := l.(*handlers.HTTPListener); ok && hl.IsTLS {
			tlsListener = hl
			break
		}
	}
	if tlsListener == nil {
		t.Fatalf("no TLS listener was built (setup problem)")
	}
	if tlsListener.Srv.TLSConfig == nil {
		t.Fatalf("TLS listener has no TLS config (setup problem)")
	}

	if tlsListener.Srv.TLSConfig.GetConfigForClient == nil {
		t.Fatalf("BUG CONFIRMED: the live TLS listener has GetConfigForClient == nil, so "+
			"tls.client_auth=%q is never applied and client certificates are not required. "+
			"The same nil removes ja3.InjectHello, so every JA3 firewall rule silently "+
			"matches nothing. Fix: keep GetConfigForClient and merge the cert lookup into it "+
			"instead of dropping it (handlers/manager.go:314 and :347).",
			def.TlsRequireAndVerify)
	}

	hello := &tls.ClientHelloInfo{ServerName: "mtls.example", Conn: pipeConn(t)}
	merged, err := tlsListener.Srv.TLSConfig.GetConfigForClient(hello)
	if err != nil {
		t.Fatalf("GetConfigForClient(mtls.example): %v", err)
	}
	if merged == nil {
		t.Fatalf("BUG CONFIRMED: GetConfigForClient returned no per-host config for a host "+
			"configured with client_auth=%q — mutual TLS is not enforced.",
			def.TlsRequireAndVerify)
	}
	if merged.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("BUG CONFIRMED: merged listener config ClientAuth=%v, want "+
			"RequireAndVerifyClientCert for client_auth=%q",
			merged.ClientAuth, def.TlsRequireAndVerify)
	}
	// The merged config replaces the whole connection config, so it must still
	// carry the certificate callback and ALPN — otherwise every handshake on an
	// mTLS host would fail ("no certificates configured") or silently downgrade
	// to HTTP/1.1.
	if merged.GetCertificate == nil {
		t.Fatalf("REGRESSION: merged config lost GetCertificate — mTLS hosts would fail the handshake")
	}
	if len(merged.NextProtos) == 0 {
		t.Fatalf("REGRESSION: merged config lost NextProtos — HTTP/2 and HTTP/3 would be disabled on mTLS hosts")
	}

	// JA3 capture must actually run now.
	if _, ok := ja3.Get(hello.Conn.RemoteAddr().String()); !ok {
		t.Errorf("BUG CONFIRMED: no JA3 fingerprint was recorded for the handshake, so " +
			"firewall ja3 rules can never match (the ja3.InjectHello wrapper was dropped)")
	}

	// Hosts without client_auth must not allocate: the callback returns (nil, nil)
	// so crypto/tls uses the base config unchanged.
	plain, err := tlsListener.Srv.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "plain.example"})
	if err != nil {
		t.Fatalf("GetConfigForClient(plain.example): %v", err)
	}
	if plain != nil {
		t.Fatalf("performance regression: a host without client_auth caused a per-handshake "+
			"tls.Config clone (%d NextProtos); the base config should be reused", len(plain.NextProtos))
	}
}

// pipeConn returns one end of an in-memory net.Pipe, used only so that
// tls.ClientHelloInfo.Conn is non-nil (ja3 keys its store by RemoteAddr).
func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() {
		_ = c1.Close()
		_ = c2.Close()
	})
	return c1
}
