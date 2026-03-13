package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync/atomic"
)

type ctxKey struct{}

var requestIDKey = &ctxKey{}

var (
	// serverPrefix is generated once on startup to ensure globally unique IDs across restarts/nodes
	serverPrefix   string
	requestCounter atomic.Uint64
)

func init() {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	serverPrefix = hex.EncodeToString(b) + "-"
}

// Generate creates a highly performant, lock-free unique request ID.
// It avoids making syscalls to /dev/urandom on the hot path.
func Generate() string {
	return serverPrefix + strconv.FormatUint(requestCounter.Add(1), 36)
}

func FromContext(ctx context.Context) string {
	if v := ctx.Value(requestIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check incoming request ID first
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = Generate()
		}

		w.Header().Del("Server")
		w.Header().Set("Server", "agbero")

		// Add to response header
		w.Header().Set("X-Request-ID", reqID)

		// Add to context for downstream use
		ctx := WithRequestID(r.Context(), reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
