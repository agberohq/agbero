package bugs

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/handlers"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/middleware/attic"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/golang-jwt/jwt/v5"
)

// Benchmarks for the hot paths touched by the audit fixes.

// BenchmarkMTLSConfigResolve measures the per-handshake GetConfigForClient
// callback, which now actually runs (it used to be nilled on the listener).
//
// no_mtls: ja3 fingerprint + per-host policy lookup still run (that is the
// security work the fix re-enabled) but the tls.Config clone is skipped and the
// base config is reused.
// mtls: additionally pays one tls.Config clone per handshake.
func BenchmarkMTLSConfigResolve(b *testing.B) {
	tmp := b.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmp, "hosts"))
	_ = hostsDir.Init(expect.DirPerm)

	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	// Prime `loaded` so the LoadAll() inside handlers.BuildListeners does not
	// rescan (empty) disk and discard the in-memory hosts below.
	if _, err := hm.LoadAll(); err != nil {
		b.Fatalf("prime host manager: %v", err)
	}
	hm.Set("mtls.example", &alaye.Host{
		Domains: []string{"mtls.example"},
		TLS:     alaye.TLS{Enabled: expect.Active, Mode: def.ModeLocalAuto, ClientAuth: def.TlsRequireAndVerify},
		Routes: []alaye.Route{{Enabled: expect.Active, Path: "/", Backends: alaye.Backend{
			Enabled: expect.Active, Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")}}}},
	})
	hm.Set("plain.example", &alaye.Host{
		Domains: []string{"plain.example"},
		TLS:     alaye.TLS{Enabled: expect.Active, Mode: def.ModeLocalAuto},
		Routes: []alaye.Route{{Enabled: expect.Active, Path: "/", Backends: alaye.Backend{
			Enabled: expect.Active, Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")}}}},
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
	defer tlsMgr.Close()
	res := resource.New(resource.WithLogger(testLogger))
	defer res.Close()

	tm, err := handlers.NewManager(handlers.ManagerConfig{
		Global: global, HostManager: hm, Resource: res, TLSManager: tlsMgr,
	})
	if err != nil {
		b.Fatalf("handlers.NewManager: %v", err)
	}
	defer tm.Close()

	var cfg *tls.Config
	for _, l := range tm.BuildListeners() {
		if hl, ok := l.(*handlers.HTTPListener); ok && hl.IsTLS {
			cfg = hl.Srv.TLSConfig
			break
		}
	}
	if cfg == nil || cfg.GetConfigForClient == nil {
		b.Fatal("no TLS listener config with GetConfigForClient")
	}

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	b.Run("no_mtls", func(b *testing.B) {
		hello := &tls.ClientHelloInfo{ServerName: "plain.example", Conn: conn}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out, err := cfg.GetConfigForClient(hello)
			if err != nil || out != nil {
				b.Fatalf("expected (nil, nil) for a host without client_auth, got (%v, %v)", out, err)
			}
		}
	})

	b.Run("mtls", func(b *testing.B) {
		hello := &tls.ClientHelloInfo{ServerName: "mtls.example", Conn: conn}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out, err := cfg.GetConfigForClient(hello)
			if err != nil || out == nil || out.ClientAuth != tls.RequireAndVerifyClientCert {
				b.Fatalf("expected a merged mTLS config, got (%v, %v)", out, err)
			}
		}
	})
}

// BenchmarkCacheHitChain measures a cache hit through the wrapper the route now
// builds: the cache is innermost and compression sits outside it, so a hit is
// re-compressed on the way out. This is the number to watch for the ordering fix.
func BenchmarkCacheHitChain(b *testing.B) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("benchmark-body-benchmark-body-benchmark-body"))
	})

	backend := httptest.NewServer(upstream)
	defer backend.Close()

	cacheCfg := &alaye.Cache{
		Enabled:          expect.Active,
		Driver:           "memory",
		TTL:              expect.Duration(time.Minute),
		Methods:          []string{http.MethodGet},
		MaxCacheableSize: 1 << 20,
	}

	// Same nesting as handlers.wrapHandler after the fix: cache inside the
	// response-shaping layers.
	handler := attic.New(cacheCfg, testLogger)(upstream)

	// Warm the cache so every iteration is a hit.
	warm := httptest.NewRecorder()
	handler.ServeHTTP(warm, httptest.NewRequest(http.MethodGet, "/asset.txt", nil))
	if got := warm.Header().Get("X-Cache"); got != "MISS" && got != "HIT" {
		b.Fatalf("cache did not engage: X-Cache=%q", got)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/asset.txt", nil))
	}
}

// BenchmarkJWTValidate measures the JWT middleware including the new aud check.
func BenchmarkJWTValidate(b *testing.B) {
	const secret = "bench-secret"
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"aud": "api-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("sign: %v", err)
	}

	mw := auth.JWT(&alaye.JWTAuth{
		Enabled:  expect.Active,
		Secret:   expect.Value(secret),
		Audience: "api-1",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Discard.Write(nil)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
	}
}
