package h3

import (
	"fmt"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// H3Middleware adds the Alt-Svc header to advertise HTTP/3 support.
// port is the string port (e.g., "443").
func H3Middleware(port string) func(http.Handler) http.Handler {
	// Cache the header value to avoid allocation per request
	// ma=2592000 means "cache this info for 30 days"
	altSvcValue := fmt.Sprintf(`h3=":%s"; ma=2592000`, port)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Advertise HTTP/3 availability
			w.Header().Set(woos.HeaderKeyAltSvc, altSvcValue)
			next.ServeHTTP(w, r)
		})
	}
}

// Helper to extract port cleanly
func ExtractPort(addr string) string {
	// Handle ":443" or "0.0.0.0:443" or "[::]:443"
	if idx := strings.LastIndex(addr, woos.Colon); idx != -1 {
		return addr[idx+1:]
	}
	return woos.DefaultHTTPSPortInt // Default fallback
}
