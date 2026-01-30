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
