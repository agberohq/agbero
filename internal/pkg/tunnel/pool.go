// Package tunnel provides outbound SOCKS5 connection pooling for agbero backends.
//
// A Pool wraps one or more SOCKS5 proxy servers and selects among them using
// either round-robin (default) or random strategy. It exposes a DialContext
// function compatible with http.Transport and net.Dialer, making it trivial
// to inject into any outbound connection path.
package tunnel

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"

	"golang.org/x/net/proxy"
)

// Pool is a thread-safe SOCKS5 proxy pool. All methods are safe for
// concurrent use by multiple goroutines.
type Pool struct {
	dialers  []proxy.Dialer
	addrs    []string // sanitised (no credentials) for logging
	counter  atomic.Uint64
	strategy string
	name     string // optional, for log context
}

// Config holds the parameters required to construct a Pool.
type Config struct {
	// Name is optional — used in error messages for named tunnel blocks.
	Name string

	// Servers is a list of host:port SOCKS5 proxy addresses.
	Servers []string

	// Username and Password are optional SOCKS5 credentials.
	// When empty, the proxy is used without authentication.
	Username string
	Password string

	// Strategy controls server selection: "round_robin" (default) or "random".
	Strategy string
}

// New constructs a Pool from the given config.
// Returns an error if any server address is invalid or if the SOCKS5
// dialer cannot be initialised.
func New(cfg Config) (*Pool, error) {
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("tunnel %q: no servers provided", cfg.Name)
	}

	var auth *proxy.Auth
	if cfg.Username != "" {
		auth = &proxy.Auth{
			User:     cfg.Username,
			Password: cfg.Password,
		}
	}

	dialers := make([]proxy.Dialer, 0, len(cfg.Servers))
	addrs := make([]string, 0, len(cfg.Servers))

	for i, s := range cfg.Servers {
		d, err := proxy.SOCKS5("tcp", s, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: server[%d] %q: %w", cfg.Name, i, s, err)
		}
		dialers = append(dialers, d)

		// Build a credential-free display address for logs.
		addrs = append(addrs, sanitiseAddr(cfg.Username, s))
	}

	strategy := cfg.Strategy
	if strategy == "" {
		strategy = "round_robin"
	}

	return &Pool{
		dialers:  dialers,
		addrs:    addrs,
		strategy: strategy,
		name:     cfg.Name,
	}, nil
}

// NewFromURL builds a single-server Pool from a socks5://[user:pass@]host:port URI.
// Used for the inline `tunnel = "socks5://..."` backend shorthand.
func NewFromURL(rawURL string) (*Pool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tunnel: invalid URI %q: %w", rawURL, err)
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("tunnel: scheme must be socks5, got %q", u.Scheme)
	}

	cfg := Config{
		Servers: []string{u.Host},
	}
	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}
	return New(cfg)
}

// DialContext implements the DialContext signature expected by http.Transport.
// It picks a server per the configured strategy and dials through it.
func (p *Pool) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := p.pick()
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	// Fallback for dialers that don't implement ContextDialer.
	// Honour context cancellation manually.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := d.Dial(network, addr)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// WrapTransport clones t and returns a new *http.Transport whose DialContext
// routes every outbound TCP connection through this pool.
//
// The cloned transport has Proxy set to nil — SOCKS5 is the proxy.
// All other transport settings (TLS config, timeouts, connection pooling)
// are preserved from the original.
func (p *Pool) WrapTransport(t *http.Transport) *http.Transport {
	clone := t.Clone()
	clone.Proxy = nil
	clone.DialContext = p.DialContext
	return clone
}

// Addrs returns the sanitised (credential-free) server addresses for logging.
func (p *Pool) Addrs() []string {
	return p.addrs
}

// Name returns the pool's name (empty for inline/anonymous pools).
func (p *Pool) Name() string {
	return p.name
}

// Len returns the number of proxy servers in this pool.
func (p *Pool) Len() int {
	return len(p.dialers)
}

// pick selects a dialer according to the configured strategy.
func (p *Pool) pick() proxy.Dialer {
	if len(p.dialers) == 1 {
		return p.dialers[0]
	}
	switch p.strategy {
	case "random":
		return p.dialers[rand.IntN(len(p.dialers))]
	default: // round_robin
		n := p.counter.Add(1) - 1
		return p.dialers[n%uint64(len(p.dialers))]
	}
}

// sanitiseAddr builds a display address without credentials.
func sanitiseAddr(username, hostPort string) string {
	if username != "" {
		return fmt.Sprintf("socks5://%s@%s", username, hostPort)
	}
	return fmt.Sprintf("socks5://%s", hostPort)
}
