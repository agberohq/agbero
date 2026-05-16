package tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// mockDialer implements proxy.Dialer and proxy.ContextDialer for testing.
type mockDialer struct {
	dialFunc        func(network, addr string) (net.Conn, error)
	dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (m *mockDialer) Dial(network, addr string) (net.Conn, error) {
	if m.dialFunc != nil {
		return m.dialFunc(network, addr)
	}
	return nil, errors.New("not implemented")
}

func (m *mockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.dialContextFunc != nil {
		return m.dialContextFunc(ctx, network, addr)
	}
	// Fallback to Dial with context support
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := m.Dial(network, addr)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// mockConn implements net.Conn for testing.
type mockConn struct {
	net.Conn
	closed bool
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockConn) Read(b []byte) (int, error)         { return 0, nil }
func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }

func TestNew(t *testing.T) {
	t.Run("valid server address format", func(t *testing.T) {
		// proxy.SOCKS5 doesn't actually connect, so any valid host:port works
		cfg := Config{
			Name:     "test-pool",
			Servers:  []string{"127.0.0.1:1080"},
			Strategy: "round_robin",
		}
		pool, err := New(cfg)
		if err != nil {
			t.Fatalf("expected no error for valid address format, got: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil pool")
		}
		if pool.Len() != 1 {
			t.Errorf("expected 1 server, got %d", pool.Len())
		}
		if pool.Name() != "test-pool" {
			t.Errorf("expected name 'test-pool', got %q", pool.Name())
		}
	})

	t.Run("no servers", func(t *testing.T) {
		cfg := Config{
			Name:    "test-pool",
			Servers: []string{},
		}
		_, err := New(cfg)
		if err == nil {
			t.Error("expected error for empty servers, got nil")
		}
		expectedErr := `tunnel "test-pool": no servers provided`
		if err.Error() != expectedErr {
			t.Errorf("expected %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("multiple servers", func(t *testing.T) {
		cfg := Config{
			Name:     "test-pool",
			Servers:  []string{"127.0.0.1:1080", "127.0.0.1:1081", "127.0.0.1:1082"},
			Strategy: "round_robin",
		}
		pool, err := New(cfg)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool.Len() != 3 {
			t.Errorf("expected 3 servers, got %d", pool.Len())
		}
	})

	t.Run("default strategy is round_robin", func(t *testing.T) {
		cfg := Config{
			Name:    "test-pool",
			Servers: []string{"127.0.0.1:1080"},
		}
		pool, err := New(cfg)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool.strategy != "round_robin" {
			t.Errorf("expected default strategy 'round_robin', got %q", pool.strategy)
		}
	})

	t.Run("with authentication", func(t *testing.T) {
		cfg := Config{
			Name:     "auth-pool",
			Servers:  []string{"127.0.0.1:1080"},
			Username: "testuser",
			Password: "testpass",
			Strategy: "random",
		}
		pool, err := New(cfg)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool.strategy != "random" {
			t.Errorf("expected strategy 'random', got %q", pool.strategy)
		}
		// Check that addresses are sanitized
		addrs := pool.Addrs()
		if len(addrs) != 1 {
			t.Fatalf("expected 1 addr, got %d", len(addrs))
		}
		expectedAddr := "socks5://testuser@127.0.0.1:1080"
		if addrs[0] != expectedAddr {
			t.Errorf("expected sanitized addr %q, got %q", expectedAddr, addrs[0])
		}
	})
}

func TestNewFromURL(t *testing.T) {
	t.Run("valid socks5 URL with auth", func(t *testing.T) {
		pool, err := NewFromURL("socks5://user:pass@127.0.0.1:1080")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil pool")
		}
		if pool.Len() != 1 {
			t.Errorf("expected 1 server, got %d", pool.Len())
		}
	})

	t.Run("valid socks5 URL without auth", func(t *testing.T) {
		pool, err := NewFromURL("socks5://127.0.0.1:1080")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool.Len() != 1 {
			t.Errorf("expected 1 server, got %d", pool.Len())
		}
	})

	t.Run("valid socks5 URL with only username", func(t *testing.T) {
		pool, err := NewFromURL("socks5://user@127.0.0.1:1080")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if pool.Len() != 1 {
			t.Errorf("expected 1 server, got %d", pool.Len())
		}
	})

	t.Run("invalid scheme - http", func(t *testing.T) {
		_, err := NewFromURL("http://127.0.0.1:1080")
		if err == nil {
			t.Error("expected error for invalid scheme")
		}
		expected := `tunnel: scheme must be socks5, got "http"`
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("invalid scheme - https", func(t *testing.T) {
		_, err := NewFromURL("https://127.0.0.1:1080")
		if err == nil {
			t.Error("expected error for invalid scheme")
		}
	})

	t.Run("malformed URL", func(t *testing.T) {
		_, err := NewFromURL("://invalid-url")
		if err == nil {
			t.Error("expected error for malformed URL")
		}
	})

	t.Run("empty URL", func(t *testing.T) {
		_, err := NewFromURL("")
		if err == nil {
			t.Error("expected error for empty URL")
		}
	})
}

func TestPool_Pick_Strategies(t *testing.T) {
	// Create a pool with mock dialers for testing strategies
	pool := &Pool{
		dialers: []proxy.Dialer{
			&mockDialer{},
			&mockDialer{},
			&mockDialer{},
		},
		addrs:    []string{"addr1", "addr2", "addr3"},
		strategy: "round_robin",
		name:     "test",
	}

	t.Run("round robin cycles through servers", func(t *testing.T) {
		pool.strategy = "round_robin"
		pool.counter.Store(0)

		// First pick should be index 0
		d1 := pool.pick()
		// Second pick should be index 1
		d2 := pool.pick()
		// Third pick should be index 2
		d3 := pool.pick()
		// Fourth pick should wrap to index 0
		d4 := pool.pick()

		if d1 != pool.dialers[0] || d2 != pool.dialers[1] ||
			d3 != pool.dialers[2] || d4 != pool.dialers[0] {
			t.Error("round robin not cycling correctly")
		}
	})

	t.Run("random picks from available servers", func(t *testing.T) {
		pool.strategy = "random"

		// Run multiple times and verify at least one different server is picked
		picks := make(map[proxy.Dialer]int)
		for i := 0; i < 100; i++ {
			picks[pool.pick()]++
		}

		if len(picks) < 2 {
			t.Error("random strategy should pick at least 2 different servers")
		}

		// Verify all picks are valid dialers
		for dialer := range picks {
			found := false
			for _, d := range pool.dialers {
				if d == dialer {
					found = true
					break
				}
			}
			if !found {
				t.Error("random picked a dialer not in the pool")
			}
		}
	})

	t.Run("single server always picked", func(t *testing.T) {
		singlePool := &Pool{
			dialers:  []proxy.Dialer{&mockDialer{}},
			strategy: "round_robin",
		}

		for i := 0; i < 10; i++ {
			if singlePool.pick() != singlePool.dialers[0] {
				t.Error("single server pool should always return the same dialer")
			}
		}
	})

	t.Run("unknown strategy defaults to round robin", func(t *testing.T) {
		pool.strategy = "unknown_strategy"
		pool.counter.Store(0)

		d1 := pool.pick()
		d2 := pool.pick()

		if d1 != pool.dialers[0] || d2 != pool.dialers[1] {
			t.Error("unknown strategy should default to round robin")
		}
	})
}

func TestPool_DialContext(t *testing.T) {
	t.Run("context cancellation with blocking dial", func(t *testing.T) {
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialFunc: func(network, addr string) (net.Conn, error) {
						time.Sleep(100 * time.Millisecond)
						return &mockConn{}, nil
					},
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := pool.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected context deadline exceeded error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded, got: %v", err)
		}
	})

	t.Run("context cancellation with ContextDialer", func(t *testing.T) {
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialContextFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(100 * time.Millisecond):
							return &mockConn{}, nil
						}
					},
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := pool.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected context deadline exceeded error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded, got: %v", err)
		}
	})

	t.Run("successful dial", func(t *testing.T) {
		expectedConn := &mockConn{}
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialFunc: func(network, addr string) (net.Conn, error) {
						return expectedConn, nil
					},
				},
			},
		}

		conn, err := pool.DialContext(context.Background(), "tcp", "example.com:80")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if conn != expectedConn {
			t.Error("unexpected connection returned")
		}
		conn.Close()
	})

	t.Run("dial error propagation", func(t *testing.T) {
		expectedErr := errors.New("connection refused")
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialFunc: func(network, addr string) (net.Conn, error) {
						return nil, expectedErr
					},
				},
			},
		}

		_, err := pool.DialContext(context.Background(), "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected %v, got %v", expectedErr, err)
		}
	})

	t.Run("context cancellation with ContextDialer that checks immediately", func(t *testing.T) {
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialContextFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
						// Check if context is already canceled
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						return &mockConn{}, nil
					},
				},
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := pool.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected context canceled error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected Canceled, got: %v (type: %T)", err, err)
		}
	})

	t.Run("context cancellation with non-context dialer", func(t *testing.T) {
		pool := &Pool{
			dialers: []proxy.Dialer{
				&mockDialer{
					dialFunc: func(network, addr string) (net.Conn, error) {
						// This one doesn't implement ContextDialer
						// so it will use the fallback in pool.DialContext
						select {
						case <-time.After(100 * time.Millisecond):
							return &mockConn{}, nil
						}
					},
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := pool.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected context deadline exceeded error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded, got: %v (type: %T)", err, err)
		}
	})
}

func TestPool_WrapTransport(t *testing.T) {
	pool := &Pool{
		dialers: []proxy.Dialer{&mockDialer{}},
	}

	t.Run("preserves transport settings", func(t *testing.T) {
		original := &http.Transport{
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		wrapped := pool.WrapTransport(original)

		if wrapped.Proxy != nil {
			t.Error("wrapped transport should have nil Proxy")
		}
		if wrapped.DialContext == nil {
			t.Error("wrapped transport should have DialContext set")
		}
		if wrapped.MaxIdleConns != original.MaxIdleConns {
			t.Errorf("expected MaxIdleConns %d, got %d", original.MaxIdleConns, wrapped.MaxIdleConns)
		}
		if wrapped.IdleConnTimeout != original.IdleConnTimeout {
			t.Errorf("expected IdleConnTimeout %v, got %v", original.IdleConnTimeout, wrapped.IdleConnTimeout)
		}
		if wrapped.TLSHandshakeTimeout != original.TLSHandshakeTimeout {
			t.Errorf("expected TLSHandshakeTimeout %v, got %v", original.TLSHandshakeTimeout, wrapped.TLSHandshakeTimeout)
		}
	})

	t.Run("original transport unchanged", func(t *testing.T) {
		original := &http.Transport{
			MaxIdleConns: 5,
			Proxy:        http.ProxyFromEnvironment,
		}

		pool.WrapTransport(original)

		if original.Proxy == nil {
			t.Error("original transport's Proxy should not be modified")
		}
		if original.MaxIdleConns != 5 {
			t.Error("original transport's settings should not be modified")
		}
	})
}

func TestPool_Concurrency(t *testing.T) {
	pool := &Pool{
		dialers: []proxy.Dialer{
			&mockDialer{
				dialFunc: func(network, addr string) (net.Conn, error) {
					return &mockConn{}, nil
				},
			},
			&mockDialer{
				dialFunc: func(network, addr string) (net.Conn, error) {
					return &mockConn{}, nil
				},
			},
		},
		strategy: "round_robin",
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Launch 100 concurrent dials
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := pool.DialContext(context.Background(), "tcp", "example.com:80")
			if err != nil {
				errCh <- err
				return
			}
			conn.Close()
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent dial error: %v", err)
	}
}

func TestSanitiseAddr(t *testing.T) {
	tests := []struct {
		name     string
		username string
		hostPort string
		expected string
	}{
		{
			name:     "with credentials",
			username: "user",
			hostPort: "localhost:1080",
			expected: "socks5://user@localhost:1080",
		},
		{
			name:     "without credentials",
			username: "",
			hostPort: "localhost:1080",
			expected: "socks5://localhost:1080",
		},
		{
			name:     "ip address with credentials",
			username: "proxyuser",
			hostPort: "192.168.1.1:1080",
			expected: "socks5://proxyuser@192.168.1.1:1080",
		},
		{
			name:     "domain with port",
			username: "admin",
			hostPort: "proxy.example.com:1080",
			expected: "socks5://admin@proxy.example.com:1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitiseAddr(tt.username, tt.hostPort)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestPool_Methods(t *testing.T) {
	pool := &Pool{
		dialers:  []proxy.Dialer{&mockDialer{}, &mockDialer{}, &mockDialer{}},
		addrs:    []string{"addr1", "addr2", "addr3"},
		strategy: "random",
		name:     "test-pool",
	}

	t.Run("Addrs returns copy of addresses", func(t *testing.T) {
		addrs := pool.Addrs()
		if len(addrs) != 3 {
			t.Errorf("expected 3 addrs, got %d", len(addrs))
		}
		if addrs[0] != "addr1" || addrs[1] != "addr2" || addrs[2] != "addr3" {
			t.Error("Addrs returned unexpected values")
		}
	})

	t.Run("Name returns pool name", func(t *testing.T) {
		if pool.Name() != "test-pool" {
			t.Errorf("expected 'test-pool', got %q", pool.Name())
		}
	})

	t.Run("Name returns empty for unnamed pool", func(t *testing.T) {
		unnamedPool := &Pool{
			dialers: []proxy.Dialer{&mockDialer{}},
		}
		if unnamedPool.Name() != "" {
			t.Errorf("expected empty name, got %q", unnamedPool.Name())
		}
	})

	t.Run("Len returns correct count", func(t *testing.T) {
		if pool.Len() != 3 {
			t.Errorf("expected 3, got %d", pool.Len())
		}

		emptyPool := &Pool{}
		if emptyPool.Len() != 0 {
			t.Errorf("expected 0 for empty pool, got %d", emptyPool.Len())
		}
	})
}

func TestPool_CounterOverflow(t *testing.T) {
	// Test that uint64 counter overflow wraps correctly in round-robin
	pool := &Pool{
		dialers: []proxy.Dialer{
			&mockDialer{},
			&mockDialer{},
		},
		strategy: "round_robin",
	}

	// Set counter close to max uint64
	pool.counter.Store(^uint64(0) - 1) // Set to max-1

	// First pick should be at index (max-1) % 2
	d1 := pool.pick()
	// Second pick should be at index max % 2
	d2 := pool.pick()
	// Third pick should wrap to index (max+1) % 2 = (0) % 2 = 0
	d3 := pool.pick()

	// Verify we got valid dialers (no panic/overflow)
	if d1 == nil || d2 == nil || d3 == nil {
		t.Error("counter overflow should not cause nil dialers")
	}

	// Verify they're from our pool
	validDialers := map[proxy.Dialer]bool{
		pool.dialers[0]: true,
		pool.dialers[1]: true,
	}
	if !validDialers[d1] || !validDialers[d2] || !validDialers[d3] {
		t.Error("counter overflow returned unexpected dialers")
	}
}

func TestPool_EmptyName(t *testing.T) {
	// Test that empty name works correctly
	cfg := Config{
		Servers:  []string{"127.0.0.1:1080"},
		Strategy: "random",
	}
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if pool.Name() != "" {
		t.Errorf("expected empty name, got %q", pool.Name())
	}
}
