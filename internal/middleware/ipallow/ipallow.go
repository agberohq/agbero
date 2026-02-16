package ipallow

import (
	"net"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

func New(allowed []string, logger *ll.Logger) func(http.Handler) http.Handler {
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

	// If no valid IPs/nets after parsing, allow all
	if len(singleIPs) == 0 && len(ipNets) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIPStr := clientip.ClientIP(r)
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
