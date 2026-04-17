// Constants used during configuration parsing and validation.
package def

import "time"

const (
	ModeLocalAuto = "auto" // Auto-generate local certificates
)

// Strategy constants
const (
	StrategyRandom            = "random"
	StrategyLeastConn         = "least_conn"
	StrategyRoundRobin        = "round_robin"
	StrategyIPHash            = "ip_hash"
	StrategyURLHash           = "url_hash"
	StrategyWeightedLeastConn = "weighted_least_conn"
	StrategyLeastResponseTime = "least_response_time"
	StrategyPowerOfTwoChoices = "power_of_two"
	StrategyConsistentHash    = "consistent_hash"
	StrategyAdaptive          = "adaptive"
	StrategySticky            = "sticky"
)

var ValidStrategies = map[string]bool{
	StrategyRandom:            true,
	StrategyLeastConn:         true,
	StrategyRoundRobin:        true,
	StrategyIPHash:            true,
	StrategyURLHash:           true,
	StrategyWeightedLeastConn: true,
	StrategyLeastResponseTime: true,
	StrategyPowerOfTwoChoices: true,
	StrategyConsistentHash:    true,
	StrategyAdaptive:          true,
	StrategySticky:            true,
}

// TLS modes
type TlsMode string

const (
	ModeLocalNone   TlsMode = "none"
	ModeLocalCert   TlsMode = "local"
	ModeLetsEncrypt TlsMode = "letsencrypt"
	ModeCustomCA    TlsMode = "custom_ca"

	TlsNone             = "none"
	TlsRequest          = "request"
	TlsRequire          = "require"
	TlsVerifyIfGiven    = "verify_if_given"
	TlsRequireAndVerify = "require_and_verify"
)

// Default timeouts
const (
	DefaultReadTimeout        = 10 * time.Second
	DefaultWriteTimeout       = 30 * time.Second
	DefaultIdleTimeout        = 120 * time.Second
	DefaultReadHeaderTimeout  = 5 * time.Second
	DefaultProxyFlushInterval = 100 * time.Millisecond
)

// Default limits
const (
	DefaultMaxHeaderBytes = 1 << 20 // 1MB
	DefaultMaxBodySize    = 2 << 20 // 2MB
)

// Wasm access capabilities
const (
	AccessHeaders = "headers"
	AccessBody    = "body"
	AccessMethod  = "method"
	AccessURI     = "uri"
	AccessConfig  = "config"
)

// Health check defaults
const (
	DefaultHealthInterval  = 10 * time.Second
	DefaultHealthTimeout   = 5 * time.Second
	DefaultHealthThreshold = 3
)

// Gossip config
const (
	DefaultGossipPort = 7946

	MinPort = 0
	MaxPort = 65535

	SecretKeyLen16 = 16
	SecretKeyLen24 = 24
	SecretKeyLen32 = 32
)

// Compression
const (
	DefaultCompressionType = "gzip"
	MinCompressionLevel    = 0
	MaxCompressionLevel    = 11
)

// Circuit breaker
const (
	DefaultCircuitBreakerThreshold = 5
	DefaultCircuitBreakerDuration  = 30 * time.Second
)

// Auth-forward
const (
	DefaultForwardAuthOnFailure = "deny"
)

// Path / routing primitives
const (
	Slash               = "/"
	Star                = "*"
	SlashStar           = "/*"
	SlashByte           = '/'
	RegexPrefix         = "~"
	TemplateOpen        = "{"
	TemplateClose       = "}"
	TemplateSep         = ":"
	TemplateWildcardKey = "*"
)

// Scheme prefixes
const (
	HTTPPrefix  = "http://"
	HTTPSPrefix = "https://"
	TCPPrefix   = "tcp://"
	UNIXPrefix  = "unix:"
)

// Git
const (
	GitModePull = "pull"
	GitModePush = "push"
	GitModeBoth = "both"
)
