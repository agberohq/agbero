package woos

import "time"

// General Info
const (
	Name         = "agbero"
	Organization = "aibox Systems"
	Display      = "agbero proxy"
	Description  = "High-performance reverse proxy / load balancer with TLS"
)

// Hosts & Network
const (
	ConfigFormatVersion = 1
	MaxPortRetries      = 10
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
	HeaderContentType     = "Content-Type"
	HeaderContentEnc      = "Content-Encoding"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXOriginalURI    = "X-Original-URI"
	HeaderXOriginalMethod = "X-Original-Method"
	HeaderXRealIP         = "X-Real-IP"
	HeaderServer          = "Server"

	HeaderXForwardedHost   = "X-Forwarded-Host"
	HeaderXForwardedProto  = "X-Forwarded-Proto"
	HeaderXForwardedServer = "X-Forwarded-Server"
	HeaderVia              = "Via"
	HeaderHost             = "Host"

	// Hop-by-hop Headers (RFC 7230 §6.1)
	HeaderKeepAlive          = "Keep-alive"
	HeaderProxyAuthenticate  = "Proxy-Authenticate"
	HeaderProxyAuthorization = "Proxy-Authorization"
	HeaderTE                 = "Te"
	HeaderTrailers           = "Trailers"
	HeaderTransferEncoding   = "Transfer-Encoding"

	HeaderCacheControl    = "Cache-Control"
	HeaderWWWAuthenticate = "WWW-Authenticate"
	HeaderKeyBearer       = "Bearer"
	HeaderKeyConnection   = "Connection"
	HeaderKeyUpgrade      = "Upgrade"
	HeaderAcceptEncoding  = "Accept-Encoding"
	HeaderKeyVary         = "Vary"
	HeaderKeyAltSvc       = "Alt-Svc"
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
	LogDir  Folder = "logs.d"
	WorkDir Folder = "work.d"

	DefaultConfigName = "agbero.hcl"
	DefaultLogName    = "agbero.log"
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
	RouteCacheTTL              = 10 * time.Minute
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
	AlpnTls = "acme-tls/1"
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
	Straight            = "|"
)

// Cache
const CacheMax = 10_000

// Route Segment Kinds
type Kind uint8

const (
	KindLiteral Kind = iota
	KindTemplate
	KindRegex
	KindCatchAll
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
	DefaultFilePermFile  = 0o666
	DefaultFilePermDir   = 0o755
	DefaultFlushInterval = 700 * time.Millisecond
	DefaultMaxBuffer     = 12_000
	DefaultVictoriaBatch = 500

	// Rotate logs at 50MB by default
	DefaultLogRotateSize = 50 * 1024 * 1024

	BufferSize = 32 * 1024

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

	EnvHome    = "HOME"
	EnvUser    = "USER"
	EnvLogName = "LOGNAME"

	MkcertPathUsrLocalBin    = "/usr/local/bin/mkcert"
	MkcertPathUsrBin         = "/usr/bin/mkcert"
	MkcertPathOptHomebrewBin = "/opt/homebrew/bin/mkcert"
	MkcertPathGoBin          = "go/bin/mkcert"
	MkcertPathLocalBin       = ".local/bin/mkcert"

	MkcertPathScoopShims = "scoop/shims/mkcert.exe"
	MkcertPathChocoBin   = "choco/bin/mkcert.exe"

	PowershellYes = "yes"

	UnixSSLCertsMakeCertRoot = "/etc/ssl/certs/mkcert-root.pem"
	UnixLocalCACertificates  = "/usr/local/share/ca-certificates/mkcert-root.crt"
	UnixHomeMakeCertRoot     = ".local/share/mkcert/rootCA.pem"

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
	URLFormat       = "http://%s:%d%s"
	URLPrefixFormat = "http://%s:%d"
)

// gossip
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
	HealthCheckJitterFraction      = 2

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

	InitialReadTimeout = 1000 * time.Millisecond
	BackendDialTimeout = 5 * time.Second

	TCPHealthCheckInterval = 5 * time.Second
	TCPHealthCheckTimeout  = 2 * time.Second

	RecordTypeHandshake      = 0x16
	HandshakeTypeClientHello = 0x01

	IdleTimeoutDeadline = 5 * time.Minute

	BackendRetry = 3

	RecordHeaderLen  = 5
	HandshakeTypeLen = 1
	HandshakeLength  = 3
	VersionLen       = 2
	RandomLen        = 32

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
	DefaultTransportDialTimeout           = 3 * time.Second
	DefaultTransportKeepAlive             = 30 * time.Second
	DefaultTransportMaxIdleConns          = 1000
	DefaultTransportMaxIdleConnsPerHost   = 100
	DefaultTransportIdleConnTimeout       = 90 * time.Second
	DefaultTransportTLSHandshakeTimeout   = 5 * time.Second
	DefaultTransportResponseHeaderTimeout = 5 * time.Second
	DefaultTransportExpectContinueTimeout = 1 * time.Second
	DefaultTransportDrainTimeout          = 30 * time.Second
)

const (
	DefaultRateTTL        = 30 * time.Minute
	DefaultRateMaxEntries = 100_000
)

// middleware
const (
	Realm                  = "Restricted"
	MaxSizeCache           = 10_000
	Allow                  = "allow"
	Deny                   = "deny"
	CacheClientMaxIdleCons = 100

	CacheClientMaxIdleTimeOuts = 90 * time.Second
	AuthorizationHeaderKey     = "Authorization"
	CookieHeaderKey            = "Cookie"
	CacheSetTTL                = 10 * time.Second
)

// folder
const (
	DirPerm         = 0755
	FilePerm        = 0644
	FilePermSecured = 0600
	SecurePerm      = 0700 // For keys/certs
)

// oauth
const (
	SessionCookieName = "agbero_sess"
	GothSessionCookie = "agbero_oauth_state"
	StateTTL          = 10 * time.Minute
	DefaultByteLen    = 16
	CallBackCodeKey   = "code"
)

const (
	ProtocolSeparator = "://"

	ProviderGoogle  = "google"
	ProviderOIDC    = "oidc"
	ProviderGitHub  = "github"
	ProviderGitLab  = "gitlab"
	ProviderGeneric = "generic"

	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

const (
	MinCompressionLevel = 0
	MaxCompressionLevel = 11
	CompressionGzip     = "gzip"
	GzipEncodingType    = "gzip"
	CompressionBrotli   = "brotli"
	BrotliEncodingType  = "br"
)
