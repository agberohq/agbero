package woos

import "time"

const (
	Name        = "agbero"
	Display     = "agbero proxy"
	Description = "High-performance reverse proxy / load balancer with Tls"
)

const (
	Localhost     = "localhost"
	LocalhostIPv4 = "127.0.0.1"
)

// Standard Headers
const (
	HeaderContentType     = "Content-Type"
	HeaderContentEnc      = "Content-Encoding"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXForwardedProto = "X-Forwarded-Proto"
	HeaderXRealIP         = "X-Real-IP"
	HeaderServer          = "Server"
)

// Standard MIME Types
const (
	MimeJSON = "application/json"
	MimeHTML = "text/html; charset=utf-8"
	MimeText = "text/plain; charset=utf-8"
)

// Internal Context Keys
const (
	CtxPort = "local-port"
	CtxIP   = "client-ip"
)

const (
	Http  = "http"
	Https = "https"
)
const (
	HostDir Folder = "hosts.d"
	CertDir Folder = "certs.d"
	DataDir Folder = "data.d"
)

const (
	DefaultConfigName = "agbero.hcl"
)

const (
	Darwin  = "darwin"
	Linux   = "linux"
	Windows = "windows"
)

const (
	User = "user"
)

// srv
const (
	DefaultConfigAddr          = "disabled"
	H3KeyPrefix                = "h3@"
	RouteCacheTTL              = int64(10 * time.Minute)
	DefaultRateLimitTTL        = 30 * time.Minute
	DefaultRateLimitMaxEntries = 100_000

	//buckets

	BucketACME           = "acme"
	BucketAuth           = "auth"
	BucketAuthDisabled   = "auth_disabled"
	BucketGlobal         = "global"
	BucketGlobalDisabled = "global_disabled"

	AlpnH3  = "h3"
	AlpnH2  = "h2"
	AlpnH11 = "http/1.1"

	PrivateBindingHost = "private-binding"

	DefaultHTTPSPort = "443"
)
