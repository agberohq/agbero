package alaye

import (
	"time"
)

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

var validStrategies = map[string]bool{
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

// Default Timeouts
const (
	DefaultReadTimeout        = 10 * time.Second
	DefaultWriteTimeout       = 30 * time.Second
	DefaultIdleTimeout        = 120 * time.Second
	DefaultReadHeaderTimeout  = 5 * time.Second
	DefaultProxyFlushInterval = 100 * time.Millisecond
)

// Default Limits
const (
	DefaultMaxHeaderBytes = 1 << 20 // 1MB
	DefaultMaxBodySize    = 2 << 20 // 2MB
)

type TlsMode string

const (
	ModeLocalNone   TlsMode = "none"
	ModeLocalCert   TlsMode = "local"
	ModeLetsEncrypt TlsMode = "letsencrypt"
	ModeCustomCA    TlsMode = "custom_ca"
)

// wasm
const (
	AccessHeaders = "headers"
	AccessBody    = "body"
	AccessMethod  = "method"
	AccessURI     = "uri"
	AccessConfig  = "config"
)

// health
const (
	DefaultHealthInterval  = 10 * time.Second
	DefaultHealthTimeout   = 5 * time.Second
	DefaultHealthThreshold = 3
)

// gossip
const (
	DefaultGossipPort    = 7946
	DefaultGossipPortStr = "7946"

	MinPort = 0
	MaxPort = 65535

	SecretKeyLen16 = 16
	SecretKeyLen24 = 24
	SecretKeyLen32 = 32
)

// compression

const (
	DefaultCompressionType = "gzip"
	MinCompressionLevel    = 0
	MaxCompressionLevel    = 11
)

// circuit breaker
const (
	DefaultCircuitBreakerThreshold = 5
	DefaultCircuitBreakerDuration  = 30 * time.Second
)

// auth-forward
const (
	DefaultForwardAuthOnFailure = "deny"
)

const (
	TCP         = "tcp"
	HTTPPrefix  = "http://"
	HTTPSPrefix = "https://"
	TCPPrefix   = "tcp://"

	UNIXPrefix = "unix:"

	CompressionGzip   = "gzip"
	CompressionBrotli = "brotli"
)

const (
	Empty               = ""
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

const (
	WindowBackSlash = '\\'
	ENVProgramData  = "ProgramData"
	ETCPath         = "/etc"
)

const (
	ProtocolSeparator = "://"

	ProviderGoogle = "google"
	ProviderOIDC   = "oidc"
	ProviderGitHub = "github"

	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)
