package safedial_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/pkg/safedial"
)

func dialer() *net.Dialer {
	return &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
}

// TestNew_BlocksLoopbackIP verifies that a raw loopback IP is blocked.
func TestNew_BlocksLoopbackIP(t *testing.T) {
	dial := safedial.New(dialer(), "test")
	_, err := dial(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error for loopback address, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestNew_BlocksPrivateIPv4 verifies RFC-1918 addresses are blocked.
func TestNew_BlocksPrivateIPv4(t *testing.T) {
	cases := []string{
		"10.0.0.1:80",
		"172.16.0.1:80",
		"192.168.1.1:80",
		"169.254.169.254:80", // AWS metadata
	}
	dial := safedial.New(dialer(), "test")
	for _, addr := range cases {
		_, err := dial(context.Background(), "tcp", addr)
		if err == nil {
			t.Errorf("expected block for %s, got nil error", addr)
			continue
		}
		if !strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("addr %s: unexpected error: %v", addr, err)
		}
	}
}

// TestNew_BlocksPrivateIPv6 verifies private IPv6 ranges are blocked.
func TestNew_BlocksPrivateIPv6(t *testing.T) {
	cases := []string{
		"[::1]:80",     // loopback
		"[fc00::1]:80", // ULA
		"[fe80::1]:80", // link-local
	}
	dial := safedial.New(dialer(), "test")
	for _, addr := range cases {
		_, err := dial(context.Background(), "tcp", addr)
		if err == nil {
			t.Errorf("expected block for %s, got nil error", addr)
		}
	}
}

// TestNew_AllowsPublicIP verifies that a public IP is allowed through
// (we test this by checking the error is NOT an SSRF block — it may
// fail with connection refused, which is fine).
func TestNew_AllowsPublicIP(t *testing.T) {
	dial := safedial.New(dialer(), "test")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "8.8.8.8:53")
	// We expect either success or a non-SSRF error (connection refused,
	// timeout, etc.). An SSRF block error here would be the bug.
	if err != nil && strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("public IP 8.8.8.8 should not be blocked by SSRF guard: %v", err)
	}
}

// TestNew_PrefixInErrorMessage verifies the caller prefix appears in errors.
func TestNew_PrefixInErrorMessage(t *testing.T) {
	dial := safedial.New(dialer(), "my-component")
	_, err := dial(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "my-component") {
		t.Errorf("expected prefix 'my-component' in error %q", err.Error())
	}
}

// TestNew_BlocksHostnameResolvingToPrivate verifies that a hostname that
// resolves to a private IP is blocked (DNS-based private address attack).
func TestNew_BlocksHostnameResolvingToPrivate(t *testing.T) {
	// Start a local listener to act as a fake DNS-like test:
	// use localhost which resolves to 127.0.0.1.
	dial := safedial.New(dialer(), "test")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dial(ctx, "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected block for localhost (resolves to 127.0.0.1)")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("unexpected error for localhost: %v", err)
	}
}

// TestNew_InvalidAddress verifies malformed addresses return an error.
func TestNew_InvalidAddress(t *testing.T) {
	dial := safedial.New(dialer(), "test")
	_, err := dial(context.Background(), "tcp", "not-an-address-at-all")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

// TestNew_ContextCancellation verifies that a cancelled context is respected
// when dialling a public address.
func TestNew_ContextCancellation(t *testing.T) {
	dial := safedial.New(dialer(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := dial(ctx, "tcp", "8.8.8.8:53")
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}

// TestNew_AllowsPublicServer performs an end-to-end round-trip through a
// transport that uses the safe dialer, verifying it does not interfere with
// legitimate public connections. We use an in-process httptest.Server but
// bind it to a non-loopback address via TLSClientConfig InsecureSkipVerify
// — actually the simplest approach is to verify a transport that carries
// the safe dialer successfully completes requests to 0.0.0.0-free addresses.
//
// Since httptest.Server binds to 127.0.0.1 (private), we test the non-block
// path by constructing a transport and confirming round-trips to a local
// server succeed when AllowPrivateBackends is set (via plain net.Dialer
// without the safe wrapper), and that the safe wrapper specifically blocks
// the loopback case.
func TestNew_TransportBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Transport with safe dialer must block requests to 127.0.0.1.
	safeTransport := &http.Transport{
		DialContext: safedial.New(dialer(), "test"),
	}
	client := &http.Client{Transport: safeTransport, Timeout: 2 * time.Second}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected SSRF block for request to loopback httptest.Server")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("unexpected error (expected SSRF block): %v", err)
	}
}

// TestNew_PlainTransportAllowsLoopback confirms the inverse: a transport
// without the safe dialer reaches the httptest.Server fine.
func TestNew_PlainTransportAllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected plain transport to reach loopback server: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
