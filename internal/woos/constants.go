package woos

import "time"

// General Info

const (
	Name        = "agbero"
	Display     = "agbero proxy"
	Description = "High-performance reverse proxy / load balancer with TLS"
)

// Hosts & Network

const (
	Localhost     = "localhost"
	LocalhostIPv4 = "127.0.0.1"

	Http  = "http"
	Https = "https"
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

// MIME Types

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

// File & Folder Names

const (
	HostDir Folder = "hosts.d"
	CertDir Folder = "certs.d"
	DataDir Folder = "data.d"

	DefaultConfigName = "agbero.hcl"
)

// Operating Systems

const (
	Darwin  = "darwin"
	Linux   = "linux"
	Windows = "windows"
)

// Users

const User = "user"

// Server Defaults & Settings

const (
	DefaultConfigAddr          = "disabled"
	DefaultHTTPSPort           = "443"
	H3KeyPrefix                = "h3@"
	RouteCacheTTL              = int64(10 * time.Minute)
	DefaultRateLimitTTL        = 30 * time.Minute
	DefaultRateLimitMaxEntries = 100_000

	// Buckets
	BucketACME           = "acme"
	BucketAuth           = "auth"
	BucketAuthDisabled   = "auth_disabled"
	BucketGlobal         = "global"
	BucketGlobalDisabled = "global_disabled"

	// ALPN Protocols
	AlpnH3  = "h3"
	AlpnH2  = "h2"
	AlpnH11 = "http/1.1"

	PrivateBindingHost = "private-binding"
)

// Path & Template Constants
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

// Cache
const CacheMax = int64(10_000)

// Route Segment Kinds

type Kind uint8

const (
	KindLiteral  Kind = iota // literal segment: "/api"
	KindTemplate             // template segment: "/{id}" or "/{id:[0-9]+}"
	KindRegex                // regex segment: "/~[0-9]+"
	KindCatchAll             // "/*"
)

// Metrics

const (
	HistogramWindow = 60 * time.Second
	MinUS           = int64(1)
	MaxUS           = int64(60_000_000)
)

// Token & Security

const (
	BlockPrivateKey = "PRIVATE KEY"
	DefaultIssuer   = "agbero"
	TokenSub        = "sub"
	TokenAlg        = "alg"
)

// Setup / Logging

const (
	DefaultFilePerm      = 0o666
	DefaultFlushInterval = 700 * time.Millisecond
	DefaultMaxBuffer     = 12_000
	DefaultVictoriaBatch = 500

	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// TLS / mkcert

const (
	MkCertBinary        = "mkcert"
	MkCertRootCAFile    = "rootCA.pem"
	MkCertDefaultCAName = "mkcert development CA"
	MkCertCAROOTFlag    = "-CAROOT"

	// Environment Variables
	EnvHome    = "HOME"
	EnvUser    = "USER"
	EnvLogName = "LOGNAME"

	// Common Paths
	UnixUsrLocalBinMkCert    = "/usr/local/bin/mkcert"
	UnixUsrBinMkCert         = "/usr/bin/mkcert"
	UnixOptHomebrewBinMkCert = "/opt/homebrew/bin/mkcert"
	UnixLocalBinMkCert       = ".local/bin/mkcert"
	UnixGoBinMkCert          = "go/bin/mkcert"

	UnixSSLCertsMakeCertRoot = "/etc/ssl/certs/mkcert-root.pem"
	UnixLocalCACertificates  = "/usr/local/share/ca-certificates/mkcert-root.crt"
	UnixHomeMakeCertRoot     = ".local/share/mkcert/rootCA.pem"

	PowershellYes = "yes"
)
