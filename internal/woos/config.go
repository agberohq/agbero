package woos

import (
	"net"
	"net/http"
	"time"
)

// ---- GLOBAL CONFIG -------------------------------------------

type GlobalConfig struct {
	Bind           BindConfig `hcl:"bind"`
	HostsDir       string     `hcl:"hosts_dir"`
	LEEmail        string     `hcl:"le_email,optional"`
	LogLevel       string     `hcl:"log_level,optional"`
	Development    bool       `hcl:"development,optional"`
	TrustedProxies []string   `hcl:"trusted_proxies,optional"`

	Timeouts   TimeoutConfig   `hcl:"timeouts,block"`
	RateLimits RateLimitConfig `hcl:"rate_limits,block"`

	// Hardening / Operability
	MaxHeaderBytes int    `hcl:"max_header_bytes,optional"` // default: 1 MiB
	TLSStorageDir  string `hcl:"tls_storage_dir,optional"`  // default: "/var/lib/agbero/certmagic"
}

type BindConfig struct {
	// Arrays allow multiple ports: http = [":80", ":8080"]
	HTTP    []string `hcl:"http,optional"`
	HTTPS   []string `hcl:"https,optional"`
	Metrics string   `hcl:"metrics,optional"`
}

type TimeoutConfig struct {
	Read       string `hcl:"read,optional"`
	Write      string `hcl:"write,optional"`
	Idle       string `hcl:"idle,optional"`
	ReadHeader string `hcl:"read_header,optional"`
}

// ---- RATE LIMITING --------------------------------------------

type RateLimitConfig struct {
	TTL          string           `hcl:"ttl,optional"`         // e.g. "30m"
	MaxEntries   int64            `hcl:"max_entries,optional"` // e.g. 100000
	AuthPrefixes []string         `hcl:"auth_prefixes,optional"`
	Global       RatePolicyConfig `hcl:"global,block"`
	Auth         RatePolicyConfig `hcl:"auth,block"`
}

type RatePolicyConfig struct {
	Requests int    `hcl:"requests"`
	Window   string `hcl:"window"`
	Burst    int    `hcl:"burst,optional"`
}

// ---- HOST CONFIG ---------------------------------------------

type HostConfig struct {
	Domains   []string     `hcl:"domains"`
	BindPorts []string     `hcl:"bind_ports,optional"`
	Routes    []Route      `hcl:"route,block"`
	Web       *Web         `hcl:"web,block"`
	TLS       *TSL         `hcl:"tls,block"`
	Limits    *LimitConfig `hcl:"limits,block"`
}

type LimitConfig struct {
	MaxBodySize int64 `hcl:"max_body_size,optional"`
}

// ---- ROUTING -------------------------------------------------

type Route struct {
	Path          string   `hcl:"path,label"`
	Backends      []string `hcl:"backends"`
	StripPrefixes []string `hcl:"strip_prefixes,optional"`
	LBStrategy    string   `hcl:"lb_strategy,optional"`

	// High-Availability Configs
	HealthCheck    *HealthCheckConfig    `hcl:"health_check,block"`
	CircuitBreaker *CircuitBreakerConfig `hcl:"circuit_breaker,block"`
	Timeouts       *RouteTimeouts        `hcl:"timeouts,block"`
}

type HealthCheckConfig struct {
	Path      string `hcl:"path"`               // Required, e.g. "/health"
	Interval  string `hcl:"interval,optional"`  // Default "10s"
	Timeout   string `hcl:"timeout,optional"`   // Default "5s"
	Threshold int    `hcl:"threshold,optional"` // Default 3
}

type CircuitBreakerConfig struct {
	Expression string `hcl:"expression,optional"` // "NetworkErrorRatio() > 0.10" (Future)
	Threshold  int    `hcl:"threshold,optional"`  // Simple fail count
	Duration   string `hcl:"duration,optional"`   // Reset interval
}

type RouteTimeouts struct {
	Request string `hcl:"request,optional"` // Total request timeout
}

// ---- STATIC WEB ----------------------------------------------

type Web struct {
	Root  WebRoot `hcl:"root"`
	Index string  `hcl:"index,optional"`
}

type WebRoot string

func (w WebRoot) String() string {
	if w == "" {
		return "."
	}
	return string(w)
}

// ---- TLS -----------------------------------------------------

type TSL struct {
	Mode        TlsMode     `hcl:"mode,optional"`
	Local       LocalCert   `hcl:"local,block"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block"`
}

type LocalCert struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type LetsEncrypt struct {
	Email   string `hcl:"email,optional"`
	Staging bool   `hcl:"staging,optional"`
}

// ---- DEFAULTS ------------------------------------------------

// SharedTransport is a globally tuned transport for upstream connections.
// In a real app, you might want distinct transports per backend if requirements differ drastically,
// but a shared tuned transport is better than the default.
var SharedTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
