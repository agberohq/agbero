package h3

import (
	"fmt"
	"net/http"

	"github.com/agberohq/agbero/internal/core/woos"
)

// AdvertiseHTTP3 adds the Alt-Svc header to advertise HTTP/3 support.
// port is the string port (e.g., "443").
func AdvertiseHTTP3(port string) func(http.Handler) http.Handler {
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
