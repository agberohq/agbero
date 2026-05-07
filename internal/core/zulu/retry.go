package zulu

import (
	"context"
	"time"

	"github.com/olekukonko/jack"
)

// Do wraps an operation with the standard retry policy.
func Do(op func() error) error {
	return NewStandard().Do(context.Background(), func(_ context.Context) error {
		return op()
	})
}

// DoCtx wraps an operation with the standard retry policy, respecting cancellation.
func DoCtx(ctx context.Context, op func() error) error {
	return NewStandard().Do(ctx, func(_ context.Context) error {
		return op()
	})
}

// DoWithRetry allows passing a custom jack.Retry policy.
func DoWithRetry(r *jack.Retry, ctx context.Context, op func() error) error {
	return r.Do(ctx, func(_ context.Context) error {
		return op()
	})
}

// NewStandard returns a Retry suitable for network calls.
// 100ms base, 2s max, 3 attempts, jitter on.
func NewStandard() *jack.Retry {
	return jack.NewRetry(
		jack.RetryWithMaxAttempts(3),
		jack.RetryWithBaseDelay(100*time.Millisecond),
		jack.RetryWithMaxDelay(2*time.Second),
		jack.RetryWithJitter(true),
	)
}

// NewShort returns a Retry for quick retries (e.g. internal calls).
// 50ms base, 500ms max, 3 attempts.
func NewShort() *jack.Retry {
	return jack.NewRetry(
		jack.RetryWithMaxAttempts(3),
		jack.RetryWithBaseDelay(50*time.Millisecond),
		jack.RetryWithMaxDelay(500*time.Millisecond),
		jack.RetryWithJitter(true),
	)
}

// NewInfinite returns a Retry that never exhausts — for Accept loops.
// 1ms base, 100ms max, unlimited attempts.
func NewInfinite() *jack.Retry {
	return jack.NewRetry(
		jack.RetryWithMaxAttempts(0),
		jack.RetryWithBaseDelay(1*time.Millisecond),
		jack.RetryWithMaxDelay(100*time.Millisecond),
		jack.RetryWithJitter(true),
	)
}

// NewHealthCheckBackoff returns a Retry for backend health probes.
// 1s base, 30s max, unlimited attempts, high jitter.
func NewHealthCheckBackoff() *jack.Retry {
	return jack.NewRetry(
		jack.RetryWithMaxAttempts(0),
		jack.RetryWithBaseDelay(1*time.Second),
		jack.RetryWithMaxDelay(30*time.Second),
		jack.RetryWithJitter(true),
	)
}
