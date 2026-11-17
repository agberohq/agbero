// Package lifecycle provides admission and bounded-drain primitives for
// components that must stop admitting work before they wait for work to finish.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrDrainTimeout is returned by Wait when admitted work does not finish
// before the caller's context expires.
var ErrDrainTimeout = errors.New("lifecycle: drain timeout")

// Controller is a close-once admission gate with a bounded drain.
//
// A typical lifecycle is:
//
//	Admit()       — accept one unit of work
//	Release()     — mark that unit complete
//	Close()       — reject all future admits
//	Wait(ctx)     — wait for admitted work, bounded by ctx
//
// Admit and Release are used per connection/session, never per packet on the
// hot forwarding path. They perform no allocation.
type Controller struct {
	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
	active int
}

// New returns an open Controller.
func New() *Controller {
	c := &Controller{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Admit admits one unit of work. It returns false after Close.
func (c *Controller) Admit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.active++
	return true
}

// Release marks one admitted unit complete.
func (c *Controller) Release() {
	c.mu.Lock()
	if c.active <= 0 {
		c.mu.Unlock()
		panic("lifecycle: Release without Admit")
	}
	c.active--
	if c.active == 0 {
		c.cond.Broadcast()
	}
	c.mu.Unlock()
}

// Close rejects future admissions. It does not wait for existing work.
func (c *Controller) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// Active returns the number of admitted units still running.
func (c *Controller) Active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// Wait blocks until all admitted work has been released or ctx expires.
// It never reports success while admitted work is still running.
func (c *Controller) Wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrDrainTimeout, err)
	}

	c.mu.Lock()
	if c.active == 0 {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Wake Wait when the context is canceled.
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer stop()

	c.mu.Lock()
	defer c.mu.Unlock()
	for c.active > 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrDrainTimeout, err)
		}
		c.cond.Wait()
	}
	return nil
}
