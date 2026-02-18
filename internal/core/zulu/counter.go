package zulu

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counter provides a thread-safe counter with optional rate limiting and windowing.
// It's useful for tracking request rates, quotas, and sliding window counters.
type Counter struct {
	value   atomic.Int64
	window  time.Duration
	resetAt atomic.Int64 // UnixNano, 0 means no windowing
	onReset func(oldValue int64)
	mu      sync.Mutex
}

// CounterOptions holds configuration for Counter.
type CounterOptions struct {
	// Window is the time window for automatic reset (0 = no windowing)
	Window time.Duration
	// OnReset is called when the counter resets (receives the old value)
	OnReset func(oldValue int64)
}

// NewCounter creates a new counter.
func NewCounter() *Counter {
	return &Counter{}
}

// NewCounterWithOptions creates a new counter with options.
func NewCounterWithOptions(opts CounterOptions) *Counter {
	c := &Counter{
		window:  opts.Window,
		onReset: opts.OnReset,
	}
	if opts.Window > 0 {
		c.resetAt.Store(time.Now().Add(opts.Window).UnixNano())
	}
	return c
}

// checkReset checks and performs window reset if needed.
func (c *Counter) checkReset() {
	if c.window <= 0 {
		return
	}

	now := time.Now().UnixNano()
	resetAt := c.resetAt.Load()

	if now > resetAt && resetAt > 0 {
		c.mu.Lock()
		// Double-check under lock
		resetAt = c.resetAt.Load()
		if now > resetAt && resetAt > 0 {
			oldValue := c.value.Swap(0)
			nextReset := now + c.window.Nanoseconds()
			c.resetAt.Store(nextReset)
			if c.onReset != nil {
				c.mu.Unlock()
				c.onReset(oldValue)
				return
			}
		}
		c.mu.Unlock()
	}
}

// Inc increments the counter by 1 and returns the new value.
func (c *Counter) Inc() int64 {
	c.checkReset()
	return c.value.Add(1)
}

// Add adds n to the counter and returns the new value.
func (c *Counter) Add(n int64) int64 {
	c.checkReset()
	return c.value.Add(n)
}

// Dec decrements the counter by 1 and returns the new value.
func (c *Counter) Dec() int64 {
	c.checkReset()
	return c.value.Add(-1)
}

// Sub subtracts n from the counter and returns the new value.
func (c *Counter) Sub(n int64) int64 {
	c.checkReset()
	return c.value.Add(-n)
}

// Get returns the current counter value.
func (c *Counter) Get() int64 {
	c.checkReset()
	return c.value.Load()
}

// Set sets the counter to a specific value.
func (c *Counter) Set(n int64) {
	c.value.Store(n)
}

// Reset resets the counter to 0 and returns the old value.
func (c *Counter) Reset() int64 {
	oldValue := c.value.Swap(0)
	if c.window > 0 {
		c.resetAt.Store(time.Now().Add(c.window).UnixNano())
	}
	return oldValue
}

// CompareAndSwap atomically compares and swaps the counter value.
func (c *Counter) CompareAndSwap(old, new int64) bool {
	return c.value.CompareAndSwap(old, new)
}

// Swap atomically swaps the counter value and returns the old value.
func (c *Counter) Swap(n int64) int64 {
	return c.value.Swap(n)
}

// Window returns the counter's time window (0 if none).
func (c *Counter) Window() time.Duration {
	return c.window
}

// TimeUntilReset returns the time until the next reset (0 if no window).
func (c *Counter) TimeUntilReset() time.Duration {
	if c.window <= 0 {
		return 0
	}
	resetAt := c.resetAt.Load()
	remaining := resetAt - time.Now().UnixNano()
	if remaining < 0 {
		return 0
	}
	return time.Duration(remaining)
}
