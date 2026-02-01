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
	ConfigFormatVersion = 2
)

const (
	Localhost     = "localhost"
	LocalhostIPv4 = "127.0.0.1"

	LocalhostExact              = "localhost"
	LocalhostSuffixDotLocal     = ".local"
	LocalhostSuffixDotLocalhost = ".localhost"
	LocalhostSuffixDotTest      = ".test"

	Http  = "http"
	Https = "https"

	SchemeHTTP  = "http@"
	SchemeHTTPS = "https@"

	HCLSuffix = ".hcl"
	TCP       = "tcp"
)

// Standard Headers

const (
	HeaderContentType   = "Content-Type"
	HeaderContentEnc    = "Content-Encoding"
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
	HeaderServer        = "Server"

	HeaderXForwardedHost   = "X-Forwarded-Host"
	HeaderXForwardedProto  = "X-Forwarded-Proto"
	HeaderXForwardedServer = "X-Forwarded-Server"
	HeaderVia              = "Via"

	// Hop-by-hop Headers (RFC 7230 §6.1)
	HeaderKeepAlive          = "Keep-Alive"
	HeaderProxyAuthenticate  = "Proxy-Authenticate"
	HeaderProxyAuthorization = "Proxy-Authorization"
	HeaderTE                 = "Te"
	HeaderTrailers           = "Trailers"
	HeaderTransferEncoding   = "Transfer-Encoding"
)

// MIME Types

const (
	MimeJSON = "application/json"
	MimeHTML = "text/html; charset=utf-8"
	MimeText = "text/plain; charset=utf-8"
)

// Internal Context Keys

const (
	CtxPort         = "local-port"
	CtxIP           = "client-ip"
	CtxOriginalPath = "original-path"
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
	DefaultHTTPSPort           = 443
	DefaultHTTPSPortInt        = "443"
	H3KeyPrefix                = "h3@"
	RouteCacheTTL              = int64(10 * time.Minute)
	DefaultRateLimitTTL        = 30 * time.Minute
	DefaultRateLimitMaxEntries = 100_000

	PrivateBindingHost = "private-binding"

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

// Setup / Logging / Buffer

const (
	DefaultFilePermFile  = 0o666 // for normal files
	DefaultFilePermDir   = 0o755 // for directories / executables
	DefaultFlushInterval = 700 * time.Millisecond
	DefaultMaxBuffer     = 12_000
	DefaultVictoriaBatch = 500

	BufferSize = 32 * 1024 // generic buffer size

	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// TLS / mkcert

const (
	MkCertBinary        = "mkcert"
	MkCertWindowsExe    = "mkcert.exe"
	MkCertRootCAFile    = "rootCA.pem"
	MkCertDefaultCAName = "mkcert development CA"
	MkCertCAROOTFlag    = "-CAROOT"

	// Environment Variables
	EnvHome    = "HOME"
	EnvUser    = "USER"
	EnvLogName = "LOGNAME"

	// mkcert Common Paths
	MkcertPathUsrLocalBin    = "/usr/local/bin/mkcert"
	MkcertPathUsrBin         = "/usr/bin/mkcert"
	MkcertPathOptHomebrewBin = "/opt/homebrew/bin/mkcert"
	MkcertPathGoBin          = "go/bin/mkcert"
	MkcertPathLocalBin       = ".local/bin/mkcert"

	// Windows Home Subpaths
	MkcertPathScoopShims = "scoop/shims/mkcert.exe"
	MkcertPathChocoBin   = "choco/bin/mkcert.exe"

	PowershellYes = "yes"

	// mkcert SSL Paths
	UnixSSLCertsMakeCertRoot = "/etc/ssl/certs/mkcert-root.pem"
	UnixLocalCACertificates  = "/usr/local/share/ca-certificates/mkcert-root.crt"
	UnixHomeMakeCertRoot     = ".local/share/mkcert/rootCA.pem"

	// mkcert hints & errors
	MkcertInstallHint = "mkcert was not found. Install and run 'mkcert -install'. macOS: 'brew install mkcert' then 'mkcert -install'"
	MkcertNotFoundMsg = "mkcert is required to install the local CA root but was not found. macOS: 'brew install mkcert' then 'mkcert -install'"
)

// SAN / Certificates / Files

const (
	HomeDirPrefix        = "~/"
	LocalhostWildcardSAN = "*.localhost"
	IPv4LoopbackSAN      = "127.0.0.1"
	IPv6LoopbackSAN      = "::1"

	CertExtPEM = ".pem"
	CertExtCRT = ".crt"
	CertExtKEY = ".key"

	CAMarkerFile    = ".mkcert_ca_installed"
	FileModePrivate = 0600

	IPv6BracketOpen  = "["
	IPv6BracketClose = "]"
	Colon            = ":"
	Dot              = "."
)

// LetsEncrypt

const (
	LetsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AcmeProfileShortLived = "shortlived"
)

// woos
const (
	DefaultAuthPath = "/.well-known/agbero"
	URLFormat       = "http://%s:%d%s" // scheme + host + port + path
	URLPrefixFormat = "http://%s:%d"   // scheme + host + port
)

// gosip

const (
	DefaultGossipPort       = 7946
	DefaultPushPullInterval = 60 * time.Second
	DefaultAuthTimeout      = 2 * time.Second

	MemberlistNamePrefix = "agbero-"

	IgnoreStreamMsg1 = "Stream connection"
	IgnoreStreamMsg2 = "Initiating push/pull sync"

	LogDebug = "[DEBUG]"
	LogWarn  = "[WARN]"
	LogErr   = "[ERR]"
)

// backend

const (
	DefaultCircuitBreakerThreshold = 5
	DefaultMaxIdleConnsPerHost     = 2
	HealthCheckJitterFraction      = 2 // 50% jitter

	DefaultHealthCheckInterval  = 10 * time.Second
	DefaultHealthCheckTimeout   = 5 * time.Second
	DefaultHealthCheckThreshold = 3
)

// lb
const (
	StRoundRobin uint8 = iota
	StIPHash
	StURLHash
	StLeastConn
	StRandom
	StWeightedLeastConn
)

// tcp

const (
	AcceptLoopDeadline = 500 * time.Millisecond
	PeekBufferSize     = 4096
	InitialReadTimeout = 50 * time.Millisecond
	BackendDialTimeout = 5 * time.Second

	RecordTypeHandshake      = 0x16
	HandshakeTypeClientHello = 0x01
	RecordHeaderLen          = 5
	HandshakeTypeLen         = 1
	HandshakeLength          = 3
	VersionLen               = 2
	RandomLen                = 32

	ExtTypeServerName = 0x0000
	NameTypeHostName  = 0x00

	MinClientHelloLen = 6
)

const (
	WindowBackSlash = '\\'
	ENVProgramData  = "ProgramData"
	ETCPath         = "/etc"
)

const (
	// Dialer
	DefaultTransportDialTimeout = 3 * time.Second
	DefaultTransportKeepAlive   = 30 * time.Second

	// Connection pooling
	DefaultTransportMaxIdleConns        = 1000
	DefaultTransportMaxIdleConnsPerHost = 100

	// Timeouts
	DefaultTransportIdleConnTimeout       = 90 * time.Second
	DefaultTransportTLSHandshakeTimeout   = 5 * time.Second
	DefaultTransportResponseHeaderTimeout = 5 * time.Second
	DefaultTransportExpectContinueTimeout = 1 * time.Second
)
