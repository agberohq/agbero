package xhttp

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
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

type ConfigProxy struct {
	Strategy string
	Keys     []string
	Timeout  time.Duration
	Fallback http.Handler
}

type ConfigBackend struct {
	Route       *alaye.Route
	Domains     []string
	Logger      *ll.Logger
	Registry    *metrics.Registry
	Fallback    http.Handler
	HealthScore *health.Score
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
