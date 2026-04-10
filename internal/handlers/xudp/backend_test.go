package xudp

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	resource2 "github.com/agberohq/agbero/internal/hub/resource"
)

func testBackendConfig(addr string) BackendConfig {
	res := resource2.New()
	return BackendConfig{
		Server: alaye.Server{
			Address: alaye.Address(addr),
			Weight:  1,
		},
		Proxy: alaye.Proxy{
			Name:     "test-proxy",
			Listen:   ":3478",
			Protocol: "udp",
		},
		Resource: res,
		Logger:   res.Logger,
	}
}

func TestNewBackend_NoHealthCheck(t *testing.T) {
	cfg := testBackendConfig("127.0.0.1:19876")
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Stop()

	if !b.Alive() {
		t.Fatal("backend without prober should default to alive")
	}
	if b.Weight() <= 0 {
		t.Fatal("weight should be positive")
	}
}

func TestNewBackend_WithHealthCheck(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()

	res := resource2.New()
	cfg := BackendConfig{
		Server: alaye.Server{
			Address: alaye.Address(addr),
			Weight:  1,
		},
		Proxy: alaye.Proxy{
			Name:     "test-proxy",
			Listen:   ":3478",
			Protocol: "udp",
			HealthCheck: alaye.TCPHealthCheck{
				Enabled:  expect.Active,
				Send:     "ping",
				Expect:   "ping",
				Interval: alaye.Duration(500_000_000), // 500ms
				Timeout:  alaye.Duration(200_000_000), // 200ms
			},
		},
		Resource: res,
		Logger:   res.Logger,
	}

	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Stop()
	// Health check registered — backend exists
}

func TestBackend_Snapshot(t *testing.T) {
	cfg := testBackendConfig("127.0.0.1:19877")
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Stop()

	snap := b.Snapshot()
	if snap == nil {
		t.Fatal("snapshot should not be nil")
	}
	if snap.Address != "127.0.0.1:19877" {
		t.Fatalf("unexpected address %q", snap.Address)
	}
	if !snap.Alive {
		t.Fatal("snapshot should show alive")
	}
}

func TestBackend_ActivityTracking(t *testing.T) {
	cfg := testBackendConfig("127.0.0.1:19878")
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Stop()

	b.Activity.StartRequest()
	if b.InFlight() != 1 {
		t.Fatalf("expected 1 in-flight, got %d", b.InFlight())
	}

	b.Activity.EndRequest(1000, false)
	if b.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight after end, got %d", b.InFlight())
	}
	if b.Activity.Requests.Load() != 1 {
		t.Fatal("expected 1 total request")
	}
}

func TestBackend_StopIdempotent(t *testing.T) {
	cfg := testBackendConfig("127.0.0.1:19879")
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b.Stop()
	b.Stop() // must not panic
}

func TestBackend_BackendKeyProtocol(t *testing.T) {
	cfg := testBackendConfig("127.0.0.1:19880")
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Stop()

	if b.StatsKey.Protocol != "udp" {
		t.Fatalf("expected protocol %q, got %q", "udp", b.StatsKey.Protocol)
	}
}
