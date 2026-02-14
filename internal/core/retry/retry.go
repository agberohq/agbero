package retry

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// NewStandard returns a backoff policy suitable for network calls.
// Initial: 500ms, Max: 5s, MaxElapsed: 30s
func NewStandard() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 500 * time.Millisecond
	b.MaxInterval = 5 * time.Second
	b.MaxElapsedTime = 30 * time.Second
	b.RandomizationFactor = 0.5
	return b
}

// NewShort returns a backoff policy for quick retries (e.g. internal calls).
// Initial: 100ms, Max: 1s, MaxElapsed: 5s
func NewShort() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 100 * time.Millisecond
	b.MaxInterval = 1 * time.Second
	b.MaxElapsedTime = 5 * time.Second
	b.RandomizationFactor = 0.5
	return b
}

// NewInfinite returns a backoff policy that never expires (for Accept loops).
func NewInfinite() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Millisecond
	b.MaxInterval = 1 * time.Second
	b.MaxElapsedTime = 0 // Never stop
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
