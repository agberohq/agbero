package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type ctxKey struct{}

var requestIDKey = &ctxKey{}

func Generate() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
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
