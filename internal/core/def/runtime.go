// Constants used during proxy operation and runtime subsystems.
package def

import "time"

// Application identity

const (
	Name         = "agbero"
	Issuer       = "agbero"
	Organization = "aibox Systems"
	Display      = "agbero proxy"
	Description  = "High-performance reverse proxy / load balancer with TLS"
)

// Setup / initialization

const (
	SetupStepInit          = "init"
	SetupStepAdmin         = "admin"
	SetupStepKeeperSecrets = "keeper_secrets"
	SetupStepTOTP          = "totp"
	SetupStepLetsEncrypt   = "letsencrypt"
	SetupStepDone          = "done"
)

const (
	On  = "on"
	Off = "off"

	ConfigFormatVersion = 1
	MaxPortRetries      = 10
)

// Security / credentials

const (
	InternalAuthKeyName = "internal_auth.key"

	MinPasswordLength = 8
	JWTSecretLength   = 128
	ClusterSecretLen  = 32

	DefaultPasswordLength   = 32
	DefaultTOTPSecretLength = 16
	DefaultTOTPDigits       = 6
	DefaultTOTPPeriod       = 30
	DefaultTOTPWindow       = 1

	ChallengeTokenTTL    = 5 * time.Minute
	ChallengeTokenIssuer = "agbero-challenge"
	ChallengeSecretSize  = 32

	// DummyPassword is used in constant-time comparisons to prevent timing attacks.
	DummyPassword = "dummy-password-for-timing"

	DefaultAuthJitter = 10 * time.Millisecond

	JTIBytesSize = 16

	MinGossipSecretLen = 16
)

// Token / signing

const (
	BlockPrivateKey = "PRIVATE KEY"
	DefaultIssuer   = "agbero"
	TokenSub        = "sub"
	TokenAlg        = "alg"
)

// Networking: hosts, protocols, schemes

const (
	Localhost     = "localhost"
	LocalhostIPv4 = "127.0.0.1"

	LocalhostExact              = "localhost"
	LocalhostSuffixDotLocal     = ".local"
	LocalhostSuffixDotLocalhost = ".localhost"
	LocalhostSuffixDotTest      = ".test"
	LocalhostSuffixDotInternal  = ".internal"
)

const (
	Http    = "http"
	Https   = "https"
	TCP     = "tcp"
	UDP     = "udp"
	FastCGI = "cgi" // cgi:// backend scheme — proxy-to-backend via FastCGI protocol

	SchemeHTTP  = "http@"
	SchemeHTTPS = "https@"

	ProtocolSeparator = "://"
)

const (
	DefaultConfigAddr   = "disabled"
	DefaultHTTPSPort    = 443
	DefaultHTTPSPortInt = "443"
	H3KeyPrefix         = "h3@"

	PrivateBindingHost = "private-binding"
)

// HTTP headers

const (
	HeaderContentType        = "Content-Type"
	HeaderContentEnc         = "Content-Encoding"
	HeaderXForwardedFor      = "X-Forwarded-For"
	HeaderXOriginalURI       = "X-Original-URI"
	HeaderXOriginalMethod    = "X-Original-Method"
	HeaderXRealIP            = "X-Real-IP"
	HeaderXAgberoService     = "X-Agbero-Service"
	HeaderXAgberoJTI         = "X-Agbero-JTI"
	HeaderXAgberoReplayURL   = "X-Agbero-Replay-Url"
	HeaderXAgberoReplayNonce = "X-Agbero-Replay-Nonce"
	HeaderServer             = "Server"

	HeaderXForwardedHost   = "X-Forwarded-Discovery"
	HeaderXForwardedProto  = "X-Forwarded-Proto"
	HeaderXForwardedServer = "X-Forwarded-Server"
	HeaderVia              = "Via"
	HeaderHost             = "Discovery"

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

	AuthorizationHeaderKey = "Authorization"
	CookieHeaderKey        = "Cookie"
)

// MIME types

const (
	MimeJSON = "application/json"
	MimeHTML = "text/html; charset=utf-8"
	MimeText = "text/plain; charset=utf-8"
)

// TLS / ALPN / certificates

const (
	AlpnH3  = "h3"
	AlpnH2  = "h2"
	AlpnH11 = "http/1.1"
	AlpnTls = "acme-tls/1"
)

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

	CAValidityYears       = 10
	LeafCertValidityYears = 2
)

const (
	IPv6BracketOpen  = "["
	IPv6BracketClose = "]"
	Colon            = ":"
	Dot              = "."
)

// ACME / Let's Encrypt

const (
	LetsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AcmeProfileShortLived = "shortlived"

	BucketACME = "acme"
)

// NSS / certutil

const (
	CertutilBinary = "certutil"

	NSSPathLinuxUsrBin      = "/usr/bin/certutil"
	NSSPathLinuxUsrLocalBin = "/usr/local/bin/certutil"
	NSSPathLinuxSnapBin     = "/snap/bin/certutil"

	NSSPathDarwinHomebrewBin   = "/opt/homebrew/bin/certutil"
	NSSPathDarwinUsrLocalBin   = "/usr/local/bin/certutil"
	NSSPathDarwinMozillaNSS    = "/opt/homebrew/opt/nss/bin/certutil"
	NSSPathDarwinMozillaNSSAlt = "/usr/local/opt/nss/bin/certutil"

	NSSInstallHintLinux  = "NSS certutil not found. Firefox trust store will not be updated. Install with: sudo apt-get install libnss3-tools  (Debian/Ubuntu)  or  sudo dnf install nss-tools  (Fedora/RHEL)"
	NSSInstallHintDarwin = "NSS certutil not found. Firefox trust store will not be updated. Install with: brew install nss"
	NSSInstallHintOther  = "NSS certutil not found. Firefox trust store may not be updated automatically."
)

// Transport defaults

const (
	DefaultTransportDialTimeout           = 3 * time.Second
	DefaultTransportKeepAlive             = 30 * time.Second
	DefaultTransportMaxIdleConns          = 10000
	DefaultTransportMaxIdleConnsPerHost   = 10000
	DefaultTransportIdleConnTimeout       = 90 * time.Second
	DefaultTransportTLSHandshakeTimeout   = 5 * time.Second
	DefaultTransportResponseHeaderTimeout = 5 * time.Second
	DefaultTransportExpectContinueTimeout = 1 * time.Second
	DefaultTransportDrainTimeout          = 30 * time.Second
)

const (
	TCPKeepAlivePeriod = 30 * time.Second
	TCPPoolMaxSize     = 3
)

// TCP / UDP proxy

const (
	BackendRetryCount = 3

	AcceptLoopDeadline = 500 * time.Millisecond
	PeekBufferSize     = 4096

	InitialReadTimeout = 1000 * time.Millisecond
	BackendDialTimeout = 5 * time.Second

	TCPHealthCheckInterval = 5 * time.Second
	TCPHealthCheckTimeout  = 2 * time.Second

	UDPDefaultSessionTTL    = 30 * time.Second
	UDPDefaultMaxSessions   = int64(100_000)
	UDPHealthCheckInterval  = 5 * time.Second
	UDPHealthCheckTimeout   = 2 * time.Second
	UDPDialTimeout          = 5 * time.Second
	UDPMaxSessions          = 100_000
	UDPBufSize              = 65535
	UDPSweepIntervalSeconds = 10
	UDPSweepRoutineName     = "xudp-session-sweeper"
	UDPSweepPoolSize        = 1
	// UDPWorkerPoolSize is the number of goroutines in the jack.Pool used
	// to dispatch incoming datagrams.  Using a bounded pool prevents the
	// goroutine-per-packet explosion that a UDP flood would otherwise cause.
	UDPWorkerPoolSize = 16
	// UDPPacketQueueSize is the jack.Pool queue depth.  When the queue is full
	// the receiveLoop drops the packet — correct UDP congestion behaviour.
	UDPPacketQueueSize = 4096

	DefaultReplayTimeout = 30 * time.Second

	IdleTimeoutDeadline = 5 * time.Minute
)

// TLS ClientHello parsing constants.
const (
	RecordTypeHandshake      = 0x16
	HandshakeTypeClientHello = 0x01

	RecordHeaderLen  = 5
	HandshakeTypeLen = 1
	HandshakeLength  = 3
	VersionLen       = 2
	RandomLen        = 32

	ExtTypeServerName = 0x0000
	NameTypeHostName  = 0x00

	MinClientHelloLen = 6
)

// Load balancer

// Load balancer strategy codes.
type Kind uint8

const (
	KindLiteral Kind = iota
	KindTemplate
	KindRegex
	KindCatchAll
)

const (
	StRoundRobin uint8 = iota
	StIPHash
	StURLHash
	StLeastConn
	StRandom
	StWeightedLeastConn
)

const (
	AdaptiveLearningRate   = 0.15
	StickySessionTTL       = 30 * time.Minute
	DefaultOAuthSessionTTL = 24 * time.Hour // Fallback when the IdP does not return an expiry
	StickyCacheSize        = 1024
)

// Health checks

const (
	DefaultHealthCheckInterval  = 10 * time.Second
	DefaultHealthCheckTimeout   = 5 * time.Second
	DefaultHealthCheckThreshold = 3
	HealthCheckJitterFraction   = 2

	HealthAbortThreshold = 30
	HealthAbortWindow    = 5
)

// Rate limiting

const (
	DefaultRateLimitTTL        = 30 * time.Minute
	DefaultRateLimitMaxEntries = 100_000

	DefaultRateTTL        = 30 * time.Minute
	DefaultRateMaxEntries = 100_000

	RateLimitCleanupInterval = 5 * time.Minute
)

// Auth / access control

const (
	Realm = "Restricted"
	Allow = "allow"
	Deny  = "deny"
	User  = "user"

	CacheClientMaxIdleCons     = 100
	CacheClientMaxIdleTimeOuts = 90 * time.Second
	CacheSetTTL                = 10 * time.Second

	BucketAuth         = "auth"
	BucketAuthDisabled = "auth_disabled"

	DefaultAuthPath    = "/.well-known/agbero"
	DefaultAuthTimeout = 2 * time.Second
)

// Admin auth.
const (
	AdminTokenTTL    = 8 * time.Hour
	AdminTokenIssuer = "agbero-admin"

	AdminCSPHeader = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' blob: https://d3js.org; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"
)

// OAuth / session

const (
	SessionCookieName = "agbero_sess"
	GothSessionCookie = "agbero_oauth_state"
	StateTTL          = 10 * time.Minute
	DefaultByteLen    = 16
	CallBackCodeKey   = "code"
)

const (
	ProviderGoogle  = "google"
	ProviderOIDC    = "oidc"
	ProviderGitHub  = "github"
	ProviderGitLab  = "gitlab"
	ProviderGeneric = "generic"

	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

// Gossip / cluster / memberlist

const (
	DefaultGossipTTL        = 30
	DefaultPushPullInterval = 60 * time.Second

	MemberlistNamePrefix = "agbero-"

	IgnoreStreamMsg1 = "Stream connection"
	IgnoreStreamMsg2 = "Initiating push/pull sync"

	LogDebug = "[DEBUG]"
	LogWarn  = "[WARN]"
	LogErr   = "[ERR]"
)

const (
	ClusterTombstoneTTL  = 24 * time.Hour
	ClusterLockTTL       = 60 * time.Second
	ClusterChallengeTTL  = 15 * time.Minute
	ClusterPruneInterval = 30 * time.Second
	ClusterFullSyncDelay = 2 * time.Second
	ClusterLeaveTimeout  = 5 * time.Second
)

const (
	BucketGlobal         = "global"
	BucketGlobalDisabled = "global_disabled"
)

const (
	URLFormat       = "http://%s:%d%s"
	URLPrefixFormat = "http://%s:%d"
)

// Firewall

const (
	DefaultFirewallMaxInspectBytes = int64(8192)
	FirewallCounterShards          = 64
	FirewallCounterCleanup         = 1 * time.Minute
)

// Middleware runtime defaults

const (
	DefaultForwardAuthTimeout   = 5 * time.Second
	ForwardAuthMaxBodyDefault   = int64(64 * 1024)
	DefaultCompressionLevel     = 5
	DefaultFallbackRedirectCode = 307
	DefaultFallbackProxyCode    = 200
	DefaultFallbackStaticCode   = 503
	DefaultCORSMaxAge           = 86400
	DefaultCacheTTL             = 5 * time.Minute
	DefaultRedisPort            = 6379
	DefaultRegexTimeout         = 100 * time.Millisecond
)

// Compression

const (
	CompressionGzip    = "gzip"
	GzipEncodingType   = "gzip"
	CompressionBrotli  = "brotli"
	BrotliEncodingType = "br"
	DynamicGzMaxSize   = 10 * 1024 * 1024
)

// Caching

const (
	CacheMax         = 10_000
	CacheMaxBot      = 2_000
	CacheMaxBig      = 100_000
	CacheMaxBodySize = 5 * 1024 * 1024

	DefaultCacheMaxItems = 10000
	CacheBufferSize      = 4096

	RouteCacheTTL = 10 * time.Minute
)

// Web / static file serving

const (
	WebGzCacheTTL          = 60 * time.Second
	WebPHPTimeout          = 30 * time.Second
	WebDynamicGzMinBytes   = 1024
	WebDynamicGzMaxBytes   = 512 * 1024
	WebDynamicGzTTL        = 60 * time.Second
	WebDynamicGzCacheItems = 256

	// WebMarkdownMaxBytes caps the size of a Markdown source file that will
	// be rendered server-side. Files larger than this are rejected with 413
	// rather than being read entirely into RAM. Without a limit, a large .md
	// file causes io.ReadAll to load the full content and goldmark to build an
	// AST 5-10x that size, exhausting system memory and triggering the OOM killer.
	WebMarkdownMaxBytes     = int64(2 * 1024 * 1024) // 2 MB
	DefaultPHPFPMAddr       = "127.0.0.1:9000"
	WebCacheImmutableMaxAge = 31536000
	WebCacheDefaultMaxAge   = 300
	MaxMultipartMemory      = 4 << 20 // 4MB
)

// Telemetry / metrics

// QueryRange defines a telemetry time window with its resolution.
type QueryRange struct {
	Duration   time.Duration
	Resolution time.Duration
	Label      string
}

const (
	HistogramWindow  = 60 * time.Second
	MinUS            = int64(1)
	MaxUS            = int64(60_000_000)
	HistogramSigFigs = 3
)

const (
	TelemetryRetention       = 24 * time.Hour
	TelemetryCollectInterval = 60 * time.Second
	TelemetryWriteBuffer     = 256
	TelemetryFlushInterval   = 5 * time.Second
	TelemetryBatchSize       = 100
)

var TelemetryQueryRanges = map[string]QueryRange{
	"30m": {30 * time.Minute, time.Minute, "30 minutes"},
	"1h":  {time.Hour, time.Minute, "1 hour"},
	"6h":  {6 * time.Hour, 5 * time.Minute, "6 hours"},
	"24h": {24 * time.Hour, 15 * time.Minute, "24 hours"},
}

// Logging

const (
	DefaultFilePermFile  = 0o666
	DefaultFilePermDir   = 0o755
	DefaultFlushInterval = 700 * time.Millisecond
	DefaultMaxBuffer     = 12_000
	DefaultVictoriaBatch = 500

	DefaultLogRotateSize = 50 * 1024 * 1024

	BufferSize = 32 * 1024

	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"

	LogUATruncateLen = 50
	LogMaxLineBytes  = 64 * 1024
)

// Admin server

const (
	DefaultReloadTimeout   = 30 * time.Second
	DefaultShutdownTimeout = 5 * time.Second

	DefaultAdminReadTimeout  = 10 * time.Second
	DefaultAdminWriteTimeout = 60 * time.Second
	DefaultAdminIdleTimeout  = 120 * time.Second

	DefaultAdminLogLimit    = 50
	DefaultAdminLogMaxLimit = 1000
)

// Git / cook (config reload)

const (
	DefaultGitPoolTimeout  = 1 * time.Second
	DefaultGitInterval     = 30 * time.Minute
	DefaultGitKeepVersions = 2

	CookTimeout         = 5 * time.Minute
	CookTimeoutStop     = 30 * time.Second
	CookWebhookBodySize = 1 << 20
)

// Wasm / worker

const (
	DefaultWasmTimeout   = 30 * time.Second
	DefaultWorkerTimeout = 30 * time.Second
	DefaultWorkerRestart = "on-failure"

	DefaultWorkerPoolSize  = 10
	MaxWorkerNameLen       = 64
	DefaultWorkerMaxMemory = 512 * 1024 * 1024
	DefaultWorkerMaxPIDs   = 32
	DefaultWorkerCPUWeight = 100

	WasmMemoryPages    = 512
	WasmMaxHeaderKey   = 1024
	WasmMaxHeaderValue = 4096
)

// Worker pool

const (
	PoolWorkers        = 8
	PoolQueueSize      = 10240
	LifetimeShards     = 32
	LifetimeHostShards = 4

	// DefaultBulkheadCapacity is the default concurrent-request budget per
	// route partition. Operators can override via WithBulkhead.
	DefaultBulkheadCapacity = 50
)

// Bot detection

const (
	BotCacheTTL     = 1 * time.Hour
	NotBotCacheTTL  = 24 * time.Hour
	MaxUserAgentLen = 200
)

// Self-update

const (
	GitHubReleaseAPIURL   = "https://api.github.com/repos/agberohq/agbero/releases/latest"
	UpdateFetchTimeout    = 30 * time.Second
	UpdateDownloadTimeout = 120 * time.Second
)

// Trash / retention

const (
	TrashDirName   = ".trash"
	TrashRetention = 7 * 24 * time.Hour
)

// Filesystem / config / directories

const (
	HostDir string = "hosts.d"
	CertDir string = "certs.d"
	DataDir string = "data.d"
	LogDir  string = "logs.d"
	WorkDir string = "work.d"

	DefaultConfigName = "agbero.hcl"
	DefaultLogName    = "agbero.log"
	DefaultKeeperName = "keeper.db"

	HCLSuffix          = ".hcl"
	ConfigHCLExtension = ".hcl"
	ConfigTempSuffix   = ".tmp"
	ConfigFilePerm     = 0644
	WorkDirPerm        = 0755
)

const (
	Darwin  = "darwin"
	Linux   = "linux"
	Windows = "windows"

	WindowBackSlash = '\\'
	ENVProgramData  = "ProgramData"
	ETCPath         = "/etc"
)

const (
	EnvHome    = "HOME"
	EnvUser    = "USER"
	EnvLogName = "LOGNAME"
)

// Request context keys

const (
	CtxPort         = "local-port"
	CtxIP           = "client-ip"
	CtxOriginalPath = "original-path"
)

// UI / terminal

const (
	DefaultUIIndent      = 3
	DefaultInputWidth    = 60
	SecretBoxMaxLength   = 60
	DefaultTerminalWidth = 80
)

// Keeper / secrets store

const (
	KeeperSchemeVault   = "vault"
	KeeperSchemeDefault = "default"
)

// DNS

const DNSMinLen = 12

// Miscellaneous / shared primitives

const (
	Empty    = ""
	Straight = "|"
)

const (
	MaxReliablePayloadSize    = 5 * 1024 * 1024
	MaxDecompressedConfigSize = 10 * 1024 * 1024
)

const (
	CRCShift          = 32
	DefaultUDPMatcher = "src_port"
)

const (
	// SOCKS5 is the scheme identifier for SOCKS5 tunnel backends.
	SOCKS5 = "socks5"

	// DefaultTunnelDialTimeout is the maximum time to establish a connection
	// through a SOCKS5 tunnel before giving up.
	DefaultTunnelDialTimeout = DefaultTransportDialTimeout

	// TunnelStrategyRoundRobin rotates through tunnel servers sequentially.
	TunnelStrategyRoundRobin = StrategyRoundRobin

	// TunnelStrategyRandom picks a tunnel server at random per connection.
	TunnelStrategyRandom = StrategyRandom
)
