package alaye

import (
	"github.com/olekukonko/errors"
)

// shared
var (
	ErrCannotBeEmpty = errors.New("cannot be empty")
)

var (
	ErrRootRequired      = errors.New("root is required for web block")
	ErrIndexPath         = errors.New("index cannot contain path separators")
	ErrNoAddress         = errors.New("address unix:... cannot be empty")
	ErrBadAddress        = errors.New("address must be unix:/path.sock or host:port")
	ErrNegativeThreshold = errors.New("threshold cannot be negative")
)

// wasm
var (
	ErrModulePathRequired = errors.New("wasm: module path is required")
	ErrNegativeBodySize   = errors.New("wasm: max_body_size cannot be negative")
	ErrUnknownCapability  = errors.New("wasm: unknown access capability")
)

// tls
var (
	ErrInvalidTLSMode     = errors.New("invalid TLS mode")
	ErrUnsupportedTLSMode = errors.New("unsupported TLS mode")
	ErrCertFileRequired   = errors.New("cert_file is required for local TLS")
	ErrCertFileAbsolute   = errors.New("cert_file must be an absolute path")
	ErrKeyFileRequired    = errors.New("key_file is required for local TLS")
	ErrKeyFileAbsolute    = errors.New("key_file must be an absolute path")

	ErrInvalidEmail         = errors.New("email must be a valid email address")
	ErrRootRequiredCustomCA = errors.New("root is required for custom_ca")
	ErrRootAbsolute         = errors.New("root must be an absolute path")
)

// timeout

var (
	ErrNegativeReadTimeout       = errors.New("read timeout cannot be negative")
	ErrNegativeWriteTimeout      = errors.New("write timeout cannot be negative")
	ErrNegativeIdleTimeout       = errors.New("idle timeout cannot be negative")
	ErrNegativeReadHeaderTimeout = errors.New("read_header timeout cannot be negative")
	ErrNegativeRequestTimeout    = errors.New("request timeout cannot be negative")
)

// server
var (
	ErrBackendAddressRequired = errors.New("backend address is required")
	ErrBackendInvalidScheme   = errors.New("invalid scheme")
	ErrBackendNegativeWeight  = errors.New("backend weight cannot be negative")
	ErrBackendInvalidSourceIP = errors.New("invalid source IP/CIDR condition")
)

// route

var (
	ErrRoutePathRequired      = errors.New("path is required")
	ErrRouteInvalidPrefix     = errors.New("invalid path prefix")
	ErrRouteNoBackendOrWeb    = errors.New("route must have either 'backend' blocks or a 'web' block")
	ErrRouteBothBackendAndWeb = errors.New("route cannot have both 'backend' blocks and a 'web' block")

	ErrWebRouteStripPrefixes  = errors.New("web routes cannot have strip_prefixes")
	ErrWebRouteUnsupportedLB  = errors.New("web routes only support default load balancing")
	ErrWebRouteHealthCheck    = errors.New("web routes cannot have health_check")
	ErrWebRouteCircuitBreaker = errors.New("web routes cannot have circuit_breaker")
	ErrWebRouteRootRequired   = errors.New("web root cannot be empty")

	ErrProxyRouteNoBackends        = errors.New("backends cannot be empty for proxy route")
	ErrProxyRouteInvalidStrip      = errors.New("invalid strip_fixes")
	ErrProxyRouteInvalidLBStrategy = errors.New("strategy is invalid")
)

// rate
var (
	ErrProxyRouteNegativeTTL        = errors.New("ttl cannot be negative")
	ErrProxyRouteNegativeMaxEntries = errors.New("max_entries cannot be negative")
	ErrProxyRouteInvalidAuthPrefix  = errors.New("invalid auth_prefix")

	ErrRateLimitNegativeRequests = errors.New("requests cannot be negative")
	ErrRateLimitInvalidWindow    = errors.New("window must be positive when requests > 0")
	ErrRateLimitNegativeBurst    = errors.New("burst cannot be negative")
	ErrRateLimitBurstTooSmall    = errors.New("burst cannot be less than requests")
	ErrRateLimitInvalidKeyHeader = errors.New("key_header cannot contain spaces")
)

// limit
var (
	ErrNegativeMacBodySize = errors.New("max_body_size cannot be negative")
)

//host

var (
	ErrNoDomains = errors.New("host must have at least one domain")

	ErrDomainHasProtocol = errors.New("domain must not include protocol")
	ErrInvalidPort       = errors.New("Invalid Port")
	ErrNoRoutes          = errors.New("host must have at least one route")
)

//health

var (
	ErrHealthPathRequired = errors.New("path is required for health_check")
	ErrHealthPathInvalid  = errors.New("invalid health path")

	ErrNegativeInterval       = errors.New("interval cannot be negative")
	ErrNegativeTimeout        = errors.New("timeout cannot be negative")
	ErrTimeoutExceedsInterval = errors.New("timeout cannot be greater than interval")
)

// header
var (
	ErrSetHeaderKeyEmpty   = errors.New("set header key cannot be empty")
	ErrSetHeaderValueEmpty = errors.New("empty set header value")
	ErrHeaderNameEmpty     = errors.New("header name cannot be empty")

	ErrAddHeaderKeyEmpty   = errors.New("add header key cannot be empty")
	ErrAddHeaderValueEmpty = errors.New("empty add header value")
)

// gossip
var (
	ErrInvalidSecretKey   = errors.New("secret_key must be 16, 24, or 32 bytes")
	ErrSeedEmpty          = errors.New("seed cannot be empty")
	ErrInvalidSeed        = errors.New("seed must be a valid host:port")
	ErrInvalidSeedFormat  = errors.New("invalid seed format")
	ErrPrivateKeyAbsolute = errors.New("private_key_file must be an absolute path")
)

// global
var (
	ErrInvalidProxy           = errors.New("trusted proxy must be a valid CIDR or IP address")
	ErrNegativeMaxHeaderBytes = errors.New("max_header_bytes cannot be negative")
)

// compression
var (
	ErrInvalidCompressionLevel = errors.New("compression level must be between 0 and 11")
	ErrInvalidCompressionType  = errors.New("compression type must be 'gzip' or 'brotli'")
)

// circuitBreaker
var (
	//ErrNegativeThreshold = errors.New("threshold cannot be negative")

	ErrNegativeDuration = errors.New("duration cannot be negative")
)

// bind
var (
	ErrEmptyAddress    = errors.New("address cannot be empty")
	ErrNoBindAddresses = errors.New("at least one of 'http' or 'https' bind addresses must be configured")
)

// jwt

var (
	ErrSecretRequired = errors.New("secret is required")
)

// auth-fwd
var (
	ErrForwardAuthURLRequired      = errors.New("url is required for forward_auth")
	ErrForwardAuthURLInvalid       = errors.New("url must start with http:// or https://")
	ErrForwardAuthOnFailureInvalid = errors.New("on_failure must be 'allow' or 'deny'")
)

// auth-basic
var (
	ErrEmptyUsers   = errors.New("users cannot be empty for basic_auth")
	ErrInvaliFormat = errors.New("invalid format")
)

// admin
var (
	ErrAdminAddressRequired = errors.New("admin address is required")
)

// pprof
var (
	ErrPprofPortRequired = errors.New("pprof port is required when pprof is enabled")
	ErrPprofLoopbackOnly = errors.New("pprof bind address must be a loopback address")
)

var (
	ErrFallbackRedirectURLRequired = errors.New("fallback: redirect_url required for type=redirect")
	ErrFallbackProxyURLRequired    = errors.New("fallback: proxy_url required for type=proxy")
	ErrFallbackTypeInvalid         = errors.New("fallback: type must be 'static', 'redirect', or 'proxy'")
	ErrFallbackBodyRequired        = errors.New("fallback: body required for type=static")
)
