package alaye

import (
	"github.com/olekukonko/errors"
)

var (
	ErrRootRequired = errors.New("root is required for web block")
	ErrIndexPath    = errors.New("index cannot contain path separators")
	ErrNoAddress    = errors.New("address unix:... cannot be empty")
	ErrBadAddress   = errors.New("address must be unix:/path.sock or host:port")
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
	ErrProxyRouteInvalidLBStrategy = errors.New("lb_strategy is invalid")
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
