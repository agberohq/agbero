package xtcp

//import (
//	"fmt"
//	"testing"
//
//	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
//	"git.imaxinacion.net/aibox/agbero/internal/woos"
//	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
//)
//
//func TestNewBalancer(t *testing.T) {
//	tests := []struct {
//		name     string
//		cfg      alaye.TCPRoute
//		registry *metrics.Registry
//		want     func(b *Balancer) error
//	}{
//		{
//			name: "basic round-robin with proxy protocol",
//			cfg: alaye.TCPRoute{
//				Listen:        "127.0.0.1:8080",
//				Backends:      []alaye.Server{{Address: "backend1:80", Weight: 1}, {Address: "backend2:80", Weight: 2}},
//				Strategy:      "round_robin",
//				ProxyProtocol: true,
//			},
//			registry: nil,
//			want: func(b *Balancer) error {
//				if len(b.backends) != 2 {
//					return fmt.Errorf("expected 2 backends, got %d", len(b.backends))
//				}
//				if b.strategy != woos.StRoundRobin {
//					return fmt.Errorf("expected strategy %d, got %d", woos.StRoundRobin, b.strategy)
//				}
//				if b.strategyName != alaye.StrategyRoundRobin {
//					return fmt.Errorf("expected strategy name %s, got %s", alaye.StrategyRoundRobin, b.strategyName)
//				}
//				if !b.proxyProtocol {
//					return fmt.Errorf("expected proxyProtocol true, got false")
//				}
//				if b.backends[0].Weight != 1 || b.backends[1].Weight != 2 {
//					return fmt.Errorf("unexpected weights: %d, %d", b.backends[0].Weight, b.backends[1].Weight)
//				}
//				return nil
//			},
//		},
//		{
//			name: "weight zero defaults to one",
//			cfg: alaye.TCPRoute{
//				Backends: []alaye.Server{{Address: "backend1:80", Weight: 0}},
//			},
//			want: func(b *Balancer) error {
//				if b.backends[0].Weight != 1 {
//					return fmt.Errorf("expected weight 1, got %d", b.backends[0].Weight)
//				}
//				return nil
//			},
//		},
//		{
//			name: "redis default healthcheck",
//			cfg: alaye.TCPRoute{
//				Backends:    []alaye.Server{{Address: "redis:6379"}},
//				HealthCheck: nil,
//			},
//			want: func(b *Balancer) error {
//				if string(b.backends[0].hcSend) != "PING\r\n" {
//					return fmt.Errorf("expected hcSend PING\\r\\n, got %s", string(b.backends[0].hcSend))
//				}
//				if string(b.backends[0].hcExpect) != "PONG" {
//					return fmt.Errorf("expected hcExpect PONG, got %s", string(b.backends[0].hcExpect))
//				}
//				return nil
//			},
//		},
//		{
//			name: "custom healthcheck",
//			cfg: alaye.TCPRoute{
//				Backends: []alaye.Server{{Address: "backend:80"}},
//				HealthCheck: &alaye.HealthCheck{
//					//Send:     "HELLO\\r\\n",
//					//Expect:   "WORLD",
//					Interval: 10,
//					Timeout:  5,
//				},
//			},
//			want: func(b *Balancer) error {
//				if string(b.backends[0].hcSend) != "HELLO\r\n" {
//					return fmt.Errorf("expected hcSend HELLO\\r\\n, got %s", string(b.backends[0].hcSend))
//				}
//				if string(b.backends[0].hcExpect) != "WORLD" {
//					return fmt.Errorf("expected hcExpect WORLD, got %s", string(b.backends[0].hcExpect))
//				}
//				if b.backends[0].hcInterval != 10 || b.backends[0].hcTimeout != 5 {
//					return fmt.Errorf("unexpected interval/timeout: %d/%d", b.backends[0].hcInterval, b.backends[0].hcTimeout)
//				}
//				return nil
//			},
//		},
//		{
//			name: "least_conn strategy",
//			cfg: alaye.TCPRoute{
//				Strategy: "least_conn",
//			},
//			want: func(b *Balancer) error {
//				if b.strategy != woos.StLeastConn {
//					return fmt.Errorf("expected strategy %d, got %d", woos.StLeastConn, b.strategy)
//				}
//				return nil
//			},
//		},
//		{
//			name: "random strategy",
//			cfg: alaye.TCPRoute{
//				Strategy: "random",
//			},
//			want: func(b *Balancer) error {
//				if b.strategy != woos.StRandom {
//					return fmt.Errorf("expected strategy %d, got %d", woos.StRandom, b.strategy)
//				}
//				return nil
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			b := NewBalancer(tt.cfg, tt.registry)
//			if err := tt.want(b); err != nil {
//				t.Error(err)
//			}
//		})
//	}
//}
//
//func TestBalancer_Stop(t *testing.T) {
//	cfg := alaye.TCPRoute{
//		Backends: []alaye.Server{{Address: "backend1:80"}, {Address: "backend2:80"}},
//	}
//	b := NewBalancer(cfg, nil)
//	b.Stop()
//	for i, be := range b.backends {
//		select {
//		case <-be.stop:
//			// expected closed
//		default:
//			t.Errorf("backend %d stop channel not closed", i)
//		}
//	}
//}
//
//func TestBalancer_BackendCount(t *testing.T) {
//	b := &Balancer{backends: make([]*Backend, 5)}
//	if got := b.BackendCount(); got != 5 {
//		t.Errorf("expected 5, got %d", got)
//	}
//	b = &Balancer{}
//	if got := b.BackendCount(); got != 0 {
//		t.Errorf("expected 0, got %d", got)
//	}
//}
//
//func TestBalancer_GetStrategyName(t *testing.T) {
//	b := &Balancer{strategyName: "test_strategy"}
//	if got := b.GetStrategyName(); got != "test_strategy" {
//		t.Errorf("expected test_strategy, got %s", got)
//	}
//}
//
//func TestBalancer_useProtocol(t *testing.T) {
//	tests := []struct {
//		name string
//		b    *Balancer
//		want bool
//	}{
//		{"nil balancer", nil, false},
//		{"false", &Balancer{proxyProtocol: false}, false},
//		{"true", &Balancer{proxyProtocol: true}, true},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if got := tt.b.useProtocol(); got != tt.want {
//				t.Errorf("expected %v, got %v", tt.want, got)
//			}
//		})
//	}
//}
//
//func TestBalancer_Backends(t *testing.T) {
//	backends := []*Backend{{Address: "b1"}, {Address: "b2"}}
//	b := &Balancer{backends: backends}
//	got := b.Backends()
//	if len(got) != 2 || got[0].Address != "b1" || got[1].Address != "b2" {
//		t.Errorf("expected backends %v, got %v", backends, got)
//	}
//}
//
//func TestBalancer_Pick(t *testing.T) {
//	// Helper to create balancer and set all backends alive
//	createBalancer := func(strategy string, backends []alaye.Server) *Balancer {
//		cfg := alaye.TCPRoute{
//			Backends: backends,
//			Strategy: strategy,
//		}
//		bal := NewBalancer(cfg, nil)
//		for _, be := range bal.backends {
//			be.Alive.Store(true)
//		}
//		return bal
//	}
//
//	t.Run("no backends", func(t *testing.T) {
//		b := &Balancer{}
//		if got := b.Pick(nil); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//
//	t.Run("single backend usable", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1"}})
//		if got := bal.Pick(nil); got == nil || got.Address != "b1" {
//			t.Errorf("expected b1, got %v", got)
//		}
//	})
//
//	t.Run("single backend max conns reached", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1", MaxConnections: 1}})
//		bal.backends[0].Activity.InFlight.Store(1)
//		if got := bal.Pick(nil); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//
//	t.Run("single backend not alive", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1"}})
//		bal.backends[0].Alive.Store(false)
//		if got := bal.Pick(nil); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//
//	t.Run("single backend excluded", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1"}})
//		exclude := map[*Backend]struct{}{bal.backends[0]: {}}
//		if got := bal.Pick(exclude); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//
//	t.Run("round_robin", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1"}, {Address: "b2"}, {Address: "b3"}})
//		bal.rrCounter.Store(0) // Reset for predictability
//
//		// Predictable order based on counter logic
//		expected := []string{"b2", "b3", "b1", "b2"}
//		for i, exp := range expected {
//			got := bal.Pick(nil)
//			if got == nil || got.Address != exp {
//				t.Errorf("pick %d: expected %s, got %v", i+1, exp, got)
//			}
//		}
//
//		// Exclude b2
//		exclude := map[*Backend]struct{}{bal.backends[1]: {}}
//		// Next would be b3 (continuing from counter), but simulate by picking
//		got := bal.Pick(exclude)
//		if got == nil || (got.Address != "b3" && got.Address != "b1") {
//			t.Errorf("expected b3 or b1, got %v", got)
//		}
//	})
//
//	t.Run("round_robin all unusable", func(t *testing.T) {
//		bal := createBalancer("round_robin", []alaye.Server{{Address: "b1"}, {Address: "b2"}})
//		bal.backends[0].Alive.Store(false)
//		bal.backends[1].MaxConns = 1
//		bal.backends[1].Activity.InFlight.Store(1)
//		if got := bal.Pick(nil); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//
//	t.Run("random", func(t *testing.T) {
//		bal := createBalancer("random", []alaye.Server{{Address: "b1"}, {Address: "b2"}, {Address: "b3"}})
//		for i := 0; i < 10; i++ {
//			got := bal.Pick(nil)
//			if got == nil {
//				t.Errorf("pick %d: expected non-nil", i)
//			}
//		}
//
//		// Exclude two, pick the remaining
//		exclude := map[*Backend]struct{}{bal.backends[0]: {}, bal.backends[1]: {}}
//		got := bal.Pick(exclude)
//		if got == nil || got.Address != "b3" {
//			t.Errorf("expected b3, got %v", got)
//		}
//	})
//
//	t.Run("least_conn", func(t *testing.T) {
//		bal := createBalancer("least_conn", []alaye.Server{{Address: "b1"}, {Address: "b2"}, {Address: "b3"}})
//		bal.backends[0].Activity.InFlight.Store(5)
//		bal.backends[1].Activity.InFlight.Store(1)
//		bal.backends[2].Activity.InFlight.Store(3)
//
//		got := bal.Pick(nil)
//		if got == nil || got.Address != "b2" {
//			t.Errorf("expected b2 (min 1), got %v", got)
//		}
//
//		// Equal, picks first (b1)
//		bal.backends[0].Activity.InFlight.Store(0)
//		bal.backends[1].Activity.InFlight.Store(0)
//		bal.backends[2].Activity.InFlight.Store(0)
//		got = bal.Pick(nil)
//		if got == nil || got.Address != "b1" {
//			t.Errorf("expected b1, got %v", got)
//		}
//
//		// Exclude b1, picks b2
//		exclude := map[*Backend]struct{}{bal.backends[0]: {}}
//		got = bal.Pick(exclude)
//		if got == nil || got.Address != "b2" {
//			t.Errorf("expected b2, got %v", got)
//		}
//	})
//
//	t.Run("least_conn none usable", func(t *testing.T) {
//		bal := createBalancer("least_conn", []alaye.Server{{Address: "b1"}, {Address: "b2"}})
//		bal.backends[0].Alive.Store(false)
//		bal.backends[1].Alive.Store(false)
//		if got := bal.Pick(nil); got != nil {
//			t.Errorf("expected nil, got %v", got)
//		}
//	})
//}
