package ipallow

import (
	"net"
	"net/http"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/olekukonko/ll"
)

func New(allowed []string, logger *ll.Logger, ipMgr *zulu.IPManager) func(http.Handler) http.Handler {
	if len(allowed) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	var ipNets []*net.IPNet
	var singleIPs []net.IP

	for _, s := range allowed {
		if strings.Contains(s, woos.Slash) {
			_, n, err := net.ParseCIDR(s)
			if err == nil {
				ipNets = append(ipNets, n)
			}
		} else {
			ip := net.ParseIP(s)
			if ip != nil {
				singleIPs = append(singleIPs, ip)
			}
		}
	}

	if len(singleIPs) == 0 && len(ipNets) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var clientIPStr string
			if ipMgr != nil {
				clientIPStr = ipMgr.ClientIP(r)
			} else {
				clientIPStr, _, _ = net.SplitHostPort(r.RemoteAddr)
			}

			clientIP := net.ParseIP(clientIPStr)

			if clientIP == nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			for _, ip := range singleIPs {
				if ip.Equal(clientIP) {
					next.ServeHTTP(w, r)
					return
				}
			}

			for _, n := range ipNets {
				if n.Contains(clientIP) {
					next.ServeHTTP(w, r)
					return
				}
			}

			if logger != nil {
				logger.Fields("ip", clientIPStr, "path", r.URL.Path).Debug("route ip_allow denied request")
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}
