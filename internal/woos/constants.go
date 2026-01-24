package woos

const (
	Name        = "agbero"
	Version     = "0.0.3"
	Description = "Production reverse proxy with Let's Encrypt support"
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
