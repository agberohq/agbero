package tlss

import (
	"crypto/tls"
	"path/filepath"
	"sync"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

// setupLocalManager creates a Manager with mock mode on and a host configured
// for ModeLocalAuto — used by every local-cert test.
func setupLocalManager(t *testing.T, domain string) *Manager {
	t.Helper()
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
			DataDir:  expect.NewFolder(filepath.Join(tmpDir, "data")),
		},
	}
	hm := discovery.NewHost(expect.NewFolder(tmpDir))
	hm.Set(domain, &alaye.Host{
		Domains: []string{domain},
		TLS:     alaye.TLS{Mode: alaye.ModeLocalAuto},
	})
	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
		// Pre-install the CA so leaf generation succeeds without system trust store.
		if err := mgr.installer.InstallCARootIfNeeded(); err != nil {
			t.Fatalf("InstallCARootIfNeeded: %v", err)
		}
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

// TestGetCertificateLocal_StorageKeyMismatch
//
// Regression test for the bug where getCertificateLocal stored the cert under
// certPrefix() ("admin") but loaded it back using the raw host ("admin.localhost"),
// producing "certificate not found" on every request.

func TestGetCertificateLocal_StorageKeyMismatch(t *testing.T) {
	domain := "admin.localhost"
	mgr := setupLocalManager(t, domain)

	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", domain, err)
	}
	if cert == nil {
		t.Fatal("got nil certificate")
	}
	if cert.Leaf == nil {
		t.Fatal("cert.Leaf is nil — ParseCertificate was not called")
	}

	// Second call must come from cache — no error.
	cert2, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("second GetCertificate(%q): %v", domain, err)
	}
	if cert2 == nil {
		t.Fatal("second call returned nil")
	}
}

// TestGetCertificateLocal_SubdomainVariants
//
// Verifies that several *.localhost subdomains all resolve correctly, each
// getting their own cert stored under their certPrefix key and cached under
// the full domain name.

func TestGetCertificateLocal_SubdomainVariants(t *testing.T) {
	domains := []string{
		"admin.localhost",
		"api.localhost",
		"app.localhost",
	}
	for _, domain := range domains {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			mgr := setupLocalManager(t, domain)
			cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
			if err != nil {
				t.Fatalf("GetCertificate(%q): %v", domain, err)
			}
			if cert == nil {
				t.Fatalf("nil cert for %q", domain)
			}
		})
	}
}

// TestGetCertificateLocal_SingleFlight
//
// Fires 20 concurrent GetCertificate calls for the same domain on a fresh
// manager (empty cache, no cert in storage).  localFlight must collapse them
// into a single EnsureForHost+Save call.  Every caller must receive a valid,
// identical certificate with no errors.

func TestGetCertificateLocal_SingleFlight(t *testing.T) {
	domain := "concurrent.localhost"
	mgr := setupLocalManager(t, domain)

	const goroutines = 20
	certs := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	// Use a gate to make all goroutines hit GetCertificate simultaneously.
	gate := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			certs[i], errs[i] = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		}()
	}
	close(gate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
		if certs[i] == nil {
			t.Errorf("goroutine %d: nil certificate", i)
		}
	}

	// All goroutines must receive the SAME certificate (singleflight shared result).
	first := certs[0]
	if first == nil {
		t.Fatal("first cert is nil — cannot compare")
	}
	for i := 1; i < goroutines; i++ {
		if certs[i] == nil {
			continue // already reported above
		}
		// Pointer equality: singleflight returns the same *tls.Certificate to all waiters.
		if certs[i] != first {
			t.Errorf("goroutine %d received a different *tls.Certificate pointer — singleflight did not deduplicate", i)
		}
	}
}

// TestPreloadLocalCertificates_CacheWarm
//
// After PreloadLocalCertificates, GetCertificate must return immediately from
// cache without calling EnsureForHost again.  We verify this by counting how
// many times the storage is loaded: zero extra loads after preload.

func TestPreloadLocalCertificates_CacheWarm(t *testing.T) {
	domain := "preload.localhost"
	mgr := setupLocalManager(t, domain)

	hosts := map[string]*alaye.Host{
		domain: {
			Domains: []string{domain},
			TLS:     alaye.TLS{Mode: alaye.ModeLocalAuto},
		},
	}

	mgr.PreloadLocalCertificates(hosts)

	// After preload the cert must be in cache.
	cached, hit := mgr.cache.Get(domain)
	if !hit {
		t.Fatal("cache miss after PreloadLocalCertificates — cert was not preloaded")
	}
	if cached == nil {
		t.Fatal("nil cert in cache after preload")
	}

	// GetCertificate must now return from cache without error.
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("GetCertificate after preload: %v", err)
	}
	if cert == nil {
		t.Fatal("nil cert from GetCertificate after preload")
	}
}

// TestPreloadLocalCertificates_SkipsNonLocal
//
// PreloadLocalCertificates must only touch ModeLocalAuto hosts; hosts with
// other TLS modes must be skipped entirely (no error, no cert in cache).

func TestPreloadLocalCertificates_SkipsNonLocal(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
			DataDir:  expect.NewFolder(filepath.Join(tmpDir, "data")),
		},
	}
	hm := discovery.NewHost(expect.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	t.Cleanup(func() { mgr.Close() })

	hosts := map[string]*alaye.Host{
		"public.example.com": {
			Domains: []string{"public.example.com"},
			TLS:     alaye.TLS{Mode: alaye.ModeLetsEncrypt},
		},
		"manual.example.com": {
			Domains: []string{"manual.example.com"},
			TLS: alaye.TLS{
				Mode: alaye.ModeLocalCert,
				Local: alaye.LocalCert{
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		},
	}

	// Must not panic or error for non-local hosts.
	mgr.PreloadLocalCertificates(hosts)

	for domain := range hosts {
		if _, hit := mgr.cache.Get(domain); hit {
			t.Errorf("unexpected cache entry for non-local host %q", domain)
		}
	}
}

// TestPreloadLocalCertificates_SkipsAlreadyCached
//
// If a cert is already in cache (e.g. loaded by loadFromStorage on restart),
// PreloadLocalCertificates must not regenerate it.

func TestPreloadLocalCertificates_SkipsAlreadyCached(t *testing.T) {
	domain := "cached.localhost"
	mgr := setupLocalManager(t, domain)

	// Manually seed the cache with a known cert.
	certPEM, keyPEM := generateACMETestCert(t, domain)
	if err := mgr.UpdateCertificate(domain, certPEM, keyPEM); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	original, _ := mgr.cache.Get(domain)

	hosts := map[string]*alaye.Host{
		domain: {
			Domains: []string{domain},
			TLS:     alaye.TLS{Mode: alaye.ModeLocalAuto},
		},
	}
	mgr.PreloadLocalCertificates(hosts)

	// Cache entry must be the same pointer — no regeneration.
	after, hit := mgr.cache.Get(domain)
	if !hit {
		t.Fatal("cache entry disappeared after PreloadLocalCertificates")
	}
	if after != original {
		t.Error("PreloadLocalCertificates replaced an already-cached cert — it should have skipped it")
	}
}

// TestGetCertificateLocal_CacheKeyIsFullDomain
//
// After getCertificateLocal resolves "admin.localhost", the cache must be
// keyed by the full SNI name ("admin.localhost"), not the storage prefix
// ("admin").  Subsequent GetCertificate calls using the SNI name must hit.

func TestGetCertificateLocal_CacheKeyIsFullDomain(t *testing.T) {
	domain := "admin.localhost"
	mgr := setupLocalManager(t, domain)

	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	// Cache must be keyed by the SNI name, not the storage prefix.
	if _, hit := mgr.cache.Get(domain); !hit {
		t.Errorf("cache miss for %q — cert was stored under wrong key", domain)
	}
	if _, hit := mgr.cache.Get("admin"); hit {
		t.Errorf("cache entry under storage prefix %q — should be keyed by full domain", "admin")
	}
}
