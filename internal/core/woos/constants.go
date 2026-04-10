package woos

import (
	"time"
)

const (
	Name         = "agbero"
	Issuer       = "agbero"
	Organization = "aibox Systems"
	Display      = "agbero proxy"
	Description  = "High-performance reverse proxy / load balancer with TLS"
)

const (
	InternalAuthKeyName = "internal_auth.key"
)
const (
	On  = "on"
	Off = "off"
)
const (
	ConfigFormatVersion = 1
	MaxPortRetries      = 10
)

const (
	SetupStepInit          = "init"
	SetupStepAdmin         = "admin"
	SetupStepKeeperSecrets = "keeper_secrets"
	SetupStepTOTP          = "totp"
	SetupStepLetsEncrypt   = "letsencrypt"
	SetupStepDone          = "done"
)

const (
	MinPasswordLength = 8
	JWTSecretLength   = 128
	ClusterSecretLen  = 32
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
)

const (
	MimeJSON = "application/json"
	MimeHTML = "text/html; charset=utf-8"
	MimeText = "text/plain; charset=utf-8"
)

const (
	CtxPort         = "local-port"
	CtxIP           = "client-ip"
	CtxOriginalPath = "original-path"
)

const (
	HostDir string = "hosts.d"
	CertDir string = "certs.d"
	DataDir string = "data.d"
	LogDir  string = "logs.d"
	WorkDir string = "work.d"

	DefaultConfigName = "agbero.hcl"
	DefaultLogName    = "agbero.log"
	DefaultKeeperName = "keeper.db"
)

const (
	Darwin  = "darwin"
	Linux   = "linux"
	Windows = "windows"
)

const User = "user"

const (
	DefaultConfigAddr          = "disabled"
	DefaultHTTPSPort           = 443
	DefaultHTTPSPortInt        = "443"
	H3KeyPrefix                = "h3@"
	RouteCacheTTL              = 10 * time.Minute
	DefaultRateLimitTTL        = 30 * time.Minute
	DefaultRateLimitMaxEntries = 100_000

	PrivateBindingHost = "private-binding"

	BucketACME           = "acme"
	BucketAuth           = "auth"
	BucketAuthDisabled   = "auth_disabled"
	BucketGlobal         = "global"
	BucketGlobalDisabled = "global_disabled"

	AlpnH3  = "h3"
	AlpnH2  = "h2"
	AlpnH11 = "http/1.1"
	AlpnTls = "acme-tls/1"
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
	Straight            = "|"
)

const (
	CacheMax         = 10_000
	CacheMaxBig      = 100_000
	CacheMaxBodySize = 5 * 1024 * 1024
)

type Kind uint8

const (
	KindLiteral Kind = iota
	KindTemplate
	KindRegex
	KindCatchAll
)

const (
	HistogramWindow = 60 * time.Second
	MinUS           = int64(1)
	MaxUS           = int64(60_000_000)
)

const (
	BlockPrivateKey = "PRIVATE KEY"
	DefaultIssuer   = "agbero"
	TokenSub        = "sub"
	TokenAlg        = "alg"
)

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
)

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

const (
	LetsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AcmeProfileShortLived = "shortlived"
)

const (
	DefaultAuthPath = "/.well-known/agbero"
	URLFormat       = "http://%s:%d%s"
	URLPrefixFormat = "http://%s:%d"
)

const (
	DefaultGossipPort       = 7946
	DefaultGossipTTL        = 30
	DefaultPushPullInterval = 60 * time.Second
	DefaultAuthTimeout      = 2 * time.Second

	MemberlistNamePrefix = "agbero-"

	IgnoreStreamMsg1 = "Stream connection"
	IgnoreStreamMsg2 = "Initiating push/pull sync"

	LogDebug = "[DEBUG]"
	LogWarn  = "[WARN]"
	LogErr   = "[ERR]"
)

const (
	DefaultCircuitBreakerThreshold = 5
	HealthCheckJitterFraction      = 2

	DefaultHealthCheckInterval  = 10 * time.Second
	DefaultHealthCheckTimeout   = 5 * time.Second
	DefaultHealthCheckThreshold = 3
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
	DefaultTransportMaxIdleConns          = 10000
	DefaultTransportMaxIdleConnsPerHost   = 10000
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
	DynamicGzMaxSize    = 10 * 1024 * 1024
)

const (
	PoolWorkers        = 8
	PoolQueueSize      = 10240
	LifetimeShards     = 32
	LifetimeHostShards = 4
)

const (
	DefaultReloadTimeout   = 30 * time.Second
	DefaultShutdownTimeout = 5 * time.Second
	DefaultGitPoolTimeout  = 1 * time.Second

	AdminTokenTTL = 8 * time.Hour

	AdminTokenIssuer = "agbero-admin"

	DefaultAdminReadTimeout  = 10 * time.Second
	DefaultAdminWriteTimeout = 60 * time.Second
	DefaultAdminIdleTimeout  = 120 * time.Second
)

const (
	DefaultForwardAuthTimeout      = 5 * time.Second
	DefaultFirewallMaxInspectBytes = int64(8192)
	DefaultCompressionLevel        = 5
	DefaultFallbackRedirectCode    = 307
	DefaultFallbackProxyCode       = 200
	DefaultFallbackStaticCode      = 503
	DefaultCORSMaxAge              = 86400
	DefaultCacheTTL                = 5 * time.Minute
	DefaultCacheMaxItems           = 10_000
	DefaultRedisPort               = 6379
	ForwardAuthMaxBodyDefault      = int64(64 * 1024)
)

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

const (
	LogUATruncateLen = 50

	LogMaxLineBytes = 64 * 1024
)

const (
	WebGzCacheTTL           = 60 * time.Second
	WebPHPTimeout           = 30 * time.Second
	WebDynamicGzMinBytes    = 1024
	WebDynamicGzMaxBytes    = 512 * 1024
	WebDynamicGzTTL         = 60 * time.Second
	WebDynamicGzCacheItems  = 256
	DefaultPHPFPMAddr       = "127.0.0.1:9000"
	WebCacheImmutableMaxAge = 31536000
	WebCacheDefaultMaxAge   = 300
)

const (
	TrashDirName   = ".trash"
	TrashRetention = 7 * 24 * time.Hour
)

const (
	DefaultWasmTimeout = 30 * time.Second
)

const (
	MinGossipSecretLen = 16

	DefaultRegexTimeout = 100 * time.Millisecond
)

const (
	GitHubReleaseAPIURL   = "https://api.github.com/repos/agberohq/agbero/releases/latest"
	UpdateFetchTimeout    = 30 * time.Second
	UpdateDownloadTimeout = 120 * time.Second
)

const (
	DefaultAdminLogLimit    = 50
	DefaultAdminLogMaxLimit = 1000
)
