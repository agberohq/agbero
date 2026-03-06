package xhttp

import (
	"net"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/ll"
)

var sharedBufferPool = zulu.NewBufferPool()

var hopHeaders = []string{
	woos.HeaderKeyConnection,
	woos.HeaderKeepAlive,
	woos.HeaderProxyAuthenticate,
	woos.HeaderProxyAuthorization,
	woos.HeaderTE,
	woos.HeaderTrailers,
	woos.HeaderTransferEncoding,
	woos.HeaderKeyUpgrade,
}

type ConfigBalancer struct {
	Strategy string
	Keys     []string
	Timeout  time.Duration
	Fallback http.Handler
}

type ConfigBackend struct {
	Route    *alaye.Route
	Domains  []string
	Logger   *ll.Logger
	Registry *metrics.Registry
}

type ipRule struct {
	ip   net.IP
	cidr *net.IPNet
}

// singleJoiningSlash joins two URL path segments with exactly one slash.
// Copied from net/http/httputil (internal).
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
