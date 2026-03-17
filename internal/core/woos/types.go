package woos

import "github.com/agberohq/agbero/internal/core/alaye"

type ctxKey int

const (
	PortKey ctxKey = iota
	IPKey
	OwnerKey
	ListenerCtxKey
)

// ListenerCtx carries the port string and host owner resolved at listener
// construction time. Stored under ListenerCtxKey in a single WithValue call,
// replacing the two separate CtxPort and OwnerKey insertions per request.
type ListenerCtx struct {
	Port  string
	Owner *alaye.Host
}
