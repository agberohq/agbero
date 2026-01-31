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
	ErrInvalidToken           = errors.New("invalid token")
	ErrInvalidClaims          = errors.New("invalid claims")
	ErrMissingTokenSubject    = errors.New("token missing subject")
	ErrUnexpectedSiningMethod = errors.New("unexpected signing method")
)

//mkcert

var (
	ErrMkCertCAROOTFail  = errors.New("mkcert -CAROOT failed")
	ErrMkCertEmptyCAROOT = errors.New("mkcert returned empty CAROOT")
)
