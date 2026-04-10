package woos

import (
	"github.com/olekukonko/errors"
	"github.com/olekukonko/errors/errmgr"
)

var (
	ErrDefined = errmgr.Define("ErrDefined,", "error occurred with (%s): %s")
)

var (
	ErrAlreadyExists = errors.New("reference required")
)

// server
var (
	ErrHostManagerRequired  = errors.New("host manager is required")
	ErrGlobalConfigRequired = errors.New("global config is required")
	ErrPortConflict         = errors.New("port conflict")
	ErrNoBindAddr           = errors.New("no http/https/tcp bind addresses configured")
	ErrLoggerRequired       = errors.New("logger is required")
	ErrConfigExists         = errors.New("configuration already exists")
)

// matcher

var (
	ErrEmptyPattern         = errors.New("empty pattern")
	ErrMultipleCatchAllsMsg = errors.New("multiple catch-alls not allowed")
	ErrCatchAllNotAtEndMsg  = errors.New("catch-all must be at the end")

	ErrEmptyParamName           = errors.New("empty parameter name")
	ErrDuplicateParamName       = errors.New("duplicate parameter name")
	ErrDuplicateRoute           = errors.New("duplicate route")
	ErrEmptyRegexPatternSegment = errors.New("empty regex pattern in segment")

	ErrEmptyTemplateParam = errors.New("empty template parameter")
	ErrInvalidParamRegex  = errors.New("invalid parameter regex")

	ErrEmptyPath   = errors.New("empty path")
	ErrInvalidPath = errors.New("invalid path")

	ErrUnclosedTemplate      = errors.New("unclosed template")
	ErrInvalidTemplateBraces = errors.New("invalid template braces")
)

// security

var (
	ErrInvalidPEMFile = errors.New("invalid pem file")
	ErrNotEd25519Key  = errors.New("key is not ed25519")
)

// token

var (
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidClaims       = errors.New("invalid claims")
	ErrMissingTokenSubject = errors.New("token missing subject")
)

// mkcert

var (
	ErrMkCertCAROOTFail  = errors.New("mkcert -CAROOT failed")
	ErrMkCertEmptyCAROOT = errors.New("mkcert returned empty CAROOT")
)

// parser
var (
	ErrEmptyConfigPath = errors.New("config path is empty")
)

// manager
var (
	ErrEmptyLEEmail         = errors.New("le_email is empty")
	ErrEmptyCertFile        = errors.New("cert_dir is empty")
	ErrOnDemandDenied       = errors.New("on-demand denied")
	ErrLocalTLSMissingFiles = errors.New("local tls requires cert_file and key_file")

	ErrMissingSNI            = errors.New("missing SNI")
	ErrUnknownHost           = errors.New("unknown host")
	ErrTLSDisabled           = errors.New("tls disabled")
	ErrLocalCertMissingFiles = errors.New("tls=local_cert requires tls.local cert_file and key_file")
	ErrLocalAutoNotAllowed   = errors.New("tls=local_auto is only allowed for localhost hosts")
	ErrLetsEncryptNotEnabled = errors.New("letsencrypt not enabled globally")
	ErrCustomCAMissingRoot   = errors.New("tls=custom_ca requires root cert")
	ErrUnknownTLSMode        = errors.New("unknown tls mode")

	ErrLoadCustomCARoot          = errors.New("loading custom CA root error")
	ErrInvalidCustomCAPEM        = errors.New("invalid custom CA PEM")
	ErrCustomCALocalCertRequired = errors.New("custom_ca requires local cert_file and key_file")
	ErrCertNotfound              = errors.New("cert not found")

	ErrHomeDirNotFound      = errors.New("failed to resolve user home directory")
	ErrStorageDirCreateFail = errors.New("failed to create storage directory")
)

// Installer
var (
	ErrMkCertRequired        = errors.New("mkcert is required for development TLS")
	ErrMkCertInstalledFailed = errors.New("mkcert -install failed")
	ErrMkCertFailed          = errors.New("mkcert failed")

	ErrReadCert       = errors.New("read cert")
	ErrReadKey        = errors.New("read key")
	ErrNoCertificate  = errors.New("no certificate in key pair")
	ErrX509Pair       = errors.New("x509 key pair")
	ErrParseLeaf      = errors.New("parse leaf")
	ErrExpired        = errors.New("expired")
	ErrNotYetValid    = errors.New("not yet valid")
	ErrVerifyHost     = errors.New("verify host")
	ErrVerifyWildcard = errors.New("verify wildcard via")
)

// gossip
var (
	ErrAuthEndpoint     = errors.New("auth endpoint returned non-OK status")
	ErrEmptyToken       = errors.New("empty token received from auth endpoint")
	ErrInvalidSecretKey = errors.New("gossip secret key must be 16, 24, or 32 bytes")
)

// backend
var (
	ErrBackendMissingScheme = errors.New("backend address is missing scheme")
	ErrBackendMissingHost   = errors.New("backend address is missing host")
	ErrBackendBadScheme     = errors.New("unsupported backend scheme")
	ErrInvalidSrcCond       = errors.New("invalid source ip/cidr condition")
)

// tcp

var (
	ErrShortData      = errors.New("short data")
	ErrNotTLS         = errors.New("not tls")
	ErrNotClientHello = errors.New("not client hello")
	ErrShort          = errors.New("short data during parsing")
	ErrShortSNI       = errors.New("short sni extension")
	ErrShortSNIList   = errors.New("short sni list")
	ErrShortName      = errors.New("short hostname")
	ErrShortExt       = errors.New("short ext")
)

//jwt

var (
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrUnsupportedProvider     = errors.New("unsupported provider")
	ErrInvalidAuthURL          = errors.New("auth_url (issuer) is required for oidc provider")
)

// firewall

var (
	ErrDataDirNotSet  = errors.New("data directory not set")
	ErrFailedToOpenDB = errors.New("failed to open firewall db")
)
