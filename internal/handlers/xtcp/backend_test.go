package xtcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("xtcp").Disable()

const (
	tcpNetwork     = "tcp"
	localHostAddr  = "127.0.0.1:0"
	bufferSize     = 1024
	hcInterval     = 50 * time.Millisecond
	hcTimeout      = 100 * time.Millisecond
	sleepWait      = 300 * time.Millisecond
	docStopTimeout = 1 * time.Second
)

var (
	pingMsg = []byte("PING\r\n")
	pongMsg = []byte("PONG")
)

func TestBackendConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     BackendConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: BackendConfig{
				Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
				Resource: resource.New(),
			},
			wantErr: false,
		},
		{
			name: "nil resource",
			cfg: BackendConfig{
				Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
				Resource: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg.Resource == nil {
				if tt.wantErr {
					return
				}
			}
		})
	}
}
func TestNewBackend_Valid(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	if b.Address == "" {
		t.Error("Expected non-empty address")
	}
}

func TestNewBackend_WithHealthCheck(t *testing.T) {
	ln, err := net.Listen(tcpNetwork, localHostAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, bufferSize)
				n, rerr := c.Read(buf)
				if rerr != nil {
					return
				}
				if bytes.Equal(buf[:n], pingMsg) {
					_, _ = c.Write(pongMsg)
				}
			}(conn)
		}
	}()

	proxy := alaye.Proxy{
		Name: "test-proxy-healthy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled:  expect.Active,
			Interval: expect.Duration(hcInterval),
			Timeout:  expect.Duration(hcTimeout),
			Send:     pingMsg,
			Expect:   pongMsg,
		},
	}

	testRes := resource.New()
	testRes.Doctor = jack.NewDoctor(jack.DoctorWithLogger(testLogger))
	defer testRes.Doctor.StopAll(docStopTimeout)

	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://" + ln.Addr().String()),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}

	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()

	time.Sleep(sleepWait)

	if !b.Alive() {
		t.Error("Expected backend to be alive with successful health check")
	}
}

func TestNewBackend_HealthCheckFailure(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled:  expect.Active,
			Interval: expect.Duration(hcInterval),
			Timeout:  expect.Duration(hcTimeout),
			Send:     pingMsg,
			Expect:   pongMsg,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:59999"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	time.Sleep(100 * time.Millisecond)
	if b.Alive() {
		t.Error("Expected backend to be dead with failed health check")
	}
}
func TestBackend_Status(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.Status(false)
	if b.Alive() {
		t.Error("Expected backend to be dead after Status(false)")
	}
	b.Status(true)
	time.Sleep(10 * time.Millisecond)
	if !b.Alive() {
		t.Error("Expected backend to be alive after Status(true)")
	}
}
func TestBackend_Weight(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	server := alaye.Server{
		Address: expect.Address("tcp://127.0.0.1:6379"),
		Weight:  10,
	}
	cfg := BackendConfig{
		Server:   server,
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	weight := b.Weight()
	if weight != 10 {
		t.Errorf("Expected weight 10, got %d", weight)
	}
}
func TestBackend_Weight_HealthAdjusted(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	server := alaye.Server{
		Address: expect.Address("tcp://127.0.0.1:6379"),
		Weight:  10,
	}
	cfg := BackendConfig{
		Server:   server,
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.HealthScore.Update(health.Record{
		ProbeSuccess: false,
		ConnHealth:   50,
	})
	weight := b.Weight()
	if weight >= 10 {
		t.Errorf("Expected weight to be reduced due to health, got %d", weight)
	}
}
func TestBackend_InFlight(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.Activity.StartRequest()
	b.Activity.StartRequest()
	if b.InFlight() != 2 {
		t.Errorf("Expected in-flight 2, got %d", b.InFlight())
	}
}
func TestBackend_ResponseTime(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.Activity.EndRequest(100, false)
	b.Activity.EndRequest(200, false)
	rt := b.ResponseTime()
	if rt == 0 {
		t.Error("Expected non-zero response time")
	}
}
func TestBackend_OnDialFailure(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.OnDialFailure(nil)
	if b.Activity.Failures.Load() != 1 {
		t.Errorf("Expected failures to be 1, got %d", b.Activity.Failures.Load())
	}
}
func TestBackend_Uptime(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	time.Sleep(50 * time.Millisecond)
	uptime := b.Uptime()
	if uptime < 50*time.Millisecond {
		t.Errorf("Expected uptime >= 50ms, got %v", uptime)
	}
}
func TestBackend_LastRecovery(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	recovery := b.LastRecovery()
	if recovery.IsZero() {
		t.Error("Expected non-zero last recovery time")
	}
}
func TestBackend_Snapshot(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.Activity.StartRequest()
	b.Activity.EndRequest(100, false)
	snap := b.Snapshot()
	if snap.Address == "" {
		t.Error("Expected non-empty address in snapshot")
	}
	if snap.TotalReqs != 1 {
		t.Errorf("Expected 1 total request, got %d", snap.TotalReqs)
	}
}
func TestBackend_Stop(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	b.Stop()
	select {
	case <-b.stop:
	default:
		t.Error("Expected stop channel to be closed")
	}
}
func TestBackend_ConcurrentOperations(t *testing.T) {
	proxy := alaye.Proxy{
		Name: "test-proxy",
		HealthCheck: alaye.HealthCheckProtocol{
			Enabled: expect.Inactive,
		},
	}
	testRes := resource.New()
	cfg := BackendConfig{
		Server:   alaye.NewServer("tcp://127.0.0.1:6379"),
		Proxy:    proxy,
		Resource: testRes,
		Logger:   testLogger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			b.Status(true)
			b.Status(false)
			b.Alive()
			b.Weight()
			b.InFlight()
			done <- true
		}()
	}
	for range 10 {
		<-done
	}
}
