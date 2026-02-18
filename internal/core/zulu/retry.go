package zulu

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// NewStandard returns a backoff policy suitable for network calls.
// Initial: 100ms, Max: 2s, MaxElapsed: 10s - faster recovery
func NewStandard() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 100 * time.Millisecond
	b.MaxInterval = 2 * time.Second
	b.MaxElapsedTime = 10 * time.Second
	b.RandomizationFactor = 0.3 // Lower jitter for more predictable retries
	return b
}

// NewShort returns a backoff policy for quick retries (e.g. internal calls).
// Initial: 50ms, Max: 500ms, MaxElapsed: 3s
func NewShort() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 50 * time.Millisecond
	b.MaxInterval = 500 * time.Millisecond
	b.MaxElapsedTime = 3 * time.Second
	b.RandomizationFactor = 0.3
	return b
}

// NewInfinite returns a backoff policy that never expires (for Accept loops).
// Initial: 1ms, Max: 100ms - very responsive to temporary errors
func NewInfinite() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Millisecond
	b.MaxInterval = 100 * time.Millisecond
	b.MaxElapsedTime = 0        // Never stop
	b.RandomizationFactor = 0.2 // Low jitter for tight loops
	return b
}

// NewHealthCheckBackoff returns a policy for backend health check retries.
// Used when a backend transitions from dead to potentially alive.
// Initial: 1s, Max: 30s, never stops trying
func NewHealthCheckBackoff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Second
	b.MaxInterval = 30 * time.Second
	b.MaxElapsedTime = 0        // Keep trying forever
	b.RandomizationFactor = 0.5 // Higher jitter to prevent thundering herd
	return b
}

// Do wraps an operation with the standard backoff policy.
func Do(op func() error) error {
	b := backoff.WithContext(NewStandard(), context.Background())
	return backoff.Retry(op, b)
}

// DoCtx wraps an operation with the standard backoff policy.
func DoCtx(ctx context.Context, op func() error) error {
	b := backoff.WithContext(NewStandard(), ctx)
	return backoff.Retry(op, b)
}

// DoWithBackoff allows custom backoff policy
func DoWithBackoff(b backoff.BackOff, op func() error) error {
	return backoff.Retry(op, b)
}
