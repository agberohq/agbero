package woos

import (
	"net"
	"net/http"
	"time"
)

// ---- GLOBAL CONFIG -------------------------------------------

type GlobalConfig struct {
	Bind           BindConfig      `hcl:"bind,block"`
	HostsDir       string          `hcl:"hosts_dir"`
	Gossip         *GossipConfig   `hcl:"gossip,block"`
	LEEmail        string          `hcl:"le_email,optional"`
	LogLevel       string          `hcl:"log_level,optional"`
	Development    bool            `hcl:"development,optional"`
	TrustedProxies []string        `hcl:"trusted_proxies,optional"`
	Timeouts       TimeoutConfig   `hcl:"timeouts,block"`
	RateLimits     RateLimitConfig `hcl:"rate_limits,block"`

	// Hardening / Operability
	MaxHeaderBytes int    `hcl:"max_header_bytes,optional"`
	TLSStorageDir  string `hcl:"tls_storage_dir,optional"`
}

type BindConfig struct {
	HTTP    []string `hcl:"http,optional"`
	HTTPS   []string `hcl:"https,optional"`
	Metrics string   `hcl:"metrics,optional"`
}

type GossipConfig struct {
	Enabled        bool     `hcl:"enabled"`
	Port           int      `hcl:"port,optional"`
	SecretKey      string   `hcl:"secret_key,optional"`       // Memberlist encryption key (16, 24, or 32 bytes)
	Seeds          []string `hcl:"seeds,optional"`            // Initial cluster peers
	PrivateKeyFile string   `hcl:"private_key_file,optional"` // Path to Ed25519 private key for app auth
}

type TimeoutConfig struct {
	Read       time.Duration `hcl:"read,optional"`
	Write      time.Duration `hcl:"write,optional"`
	Idle       time.Duration `hcl:"idle,optional"`
	ReadHeader time.Duration `hcl:"read_header,optional"`
}

// ---- RATE LIMITING --------------------------------------------

type RateLimitConfig struct {
	TTL          time.Duration    `hcl:"ttl,optional"`
	MaxEntries   int64            `hcl:"max_entries,optional"`
	AuthPrefixes []string         `hcl:"auth_prefixes,optional"`
	Global       RatePolicyConfig `hcl:"global,block"`
	Auth         RatePolicyConfig `hcl:"auth,block"`
}

type RatePolicyConfig struct {
	Requests int           `hcl:"requests"`
	Burst    int           `hcl:"burst,optional"`
	Window   time.Duration `hcl:"window"`
}

// ---- HOST CONFIG ---------------------------------------------

type HostConfig struct {
	Domains     []string       `hcl:"domains"`
	BindPorts   []string       `hcl:"bind_ports,optional"`
	Routes      []Route        `hcl:"route,block"`
	Web         *Web           `hcl:"web,block"`
	TLS         *TSL           `hcl:"tls,block"`
	Limits      *LimitConfig   `hcl:"limits,block"`
	Compression bool           `hcl:"compression,optional"`
	Headers     *HeadersConfig `hcl:"headers,block"`
}

type HeadersConfig struct {
	Request  *HeaderOperations `hcl:"request,block"`
	Response *HeaderOperations `hcl:"response,block"`
}

type HeaderOperations struct {
	Set    map[string]string `hcl:"set,optional"`
	Add    map[string]string `hcl:"add,optional"`
	Remove []string          `hcl:"remove,optional"`
}

type LimitConfig struct {
	MaxBodySize int64 `hcl:"max_body_size,optional"`
}

// ---- ROUTING -------------------------------------------------

type BasicAuthConfig struct {
	// List of "username:password" (Plaintext for now, or bcrypt in future)
	Users []string `hcl:"users"`
	Realm string   `hcl:"realm,optional"`
}

type ForwardAuthConfig struct {
	URL string `hcl:"url"` // e.g. "http://auth-service:8080/verify"

	// Headers to copy FROM client request TO auth service (e.g. "Authorization", "Cookie")
	RequestHeaders []string `hcl:"request_headers,optional"`

	// Headers to copy FROM auth response TO backend request (e.g. "X-User-ID")
	AuthResponseHeaders []string `hcl:"auth_response_headers,optional"`
}

type HealthCheckConfig struct {
	Path      string        `hcl:"path"`
	Interval  time.Duration `hcl:"interval,optional"`
	Timeout   time.Duration `hcl:"timeout,optional"`
	Threshold int           `hcl:"threshold,optional"`
}

type CircuitBreakerConfig struct {
	Threshold int           `hcl:"threshold,optional"`
	Duration  time.Duration `hcl:"duration,optional"`
}

type RouteTimeouts struct {
	Request time.Duration `hcl:"request,optional"`
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
	CustomCA    CustomCA    `hcl:"custom_ca,block"`
}

type LocalCert struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type LetsEncrypt struct {
	Email      string `hcl:"email,optional"`
	Staging    bool   `hcl:"staging,optional"`
	ShortLived bool   `hcl:"short_lived,optional"` // Enable 6-day certs
}

type CustomCA struct {
	Root string `hcl:"root"` // CA cert file path
}

// ---- DEFAULTS ------------------------------------------------

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
