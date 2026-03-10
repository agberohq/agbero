package health

import (
	"context"
	"time"
)

// Executor abstracts the specific health check logic (HTTP vs TCP)
type Executor interface {
	// Probe performs the health check.
	// It returns success status, latency, and any error encountered.
	Probe(ctx context.Context) (success bool, latency time.Duration, err error)
}
