package woos

import (
	"context"
	"time"
)

// SharedState defines the distributed state backend used across cluster nodes.
// Implementations provide atomic counters and rate limit buckets that work
// consistently whether backed by Redis or any other distributed store.
// The zero value (nil) is valid — callers must check before use.
type SharedState interface {
	Increment(ctx context.Context, key string, window time.Duration) (int64, error)
	AllowRateLimit(ctx context.Context, key string, limit int, window time.Duration, burst int) (bool, error)
	Close() error
}
