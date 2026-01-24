package woos

const (
	Name        = "agbero"
	Description = "Production reverse proxy automatic Tls. "
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
	HostDir Folder = "./hosts.d"
	CertDir Folder = "./certs.d"
)

const (
	DefaultConfigName = "./agbero.hcl"
)
