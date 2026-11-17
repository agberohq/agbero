package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAdmitRejectedAfterClose(t *testing.T) {
	c := New()
	if !c.Admit() {
		t.Fatal("initial Admit failed")
	}
	c.Release()
	c.Close()
	if c.Admit() {
		t.Fatal("Admit succeeded after Close")
	}
}

func TestWaitDoesNotReportFalseSuccess(t *testing.T) {
	c := New()
	if !c.Admit() {
		t.Fatal("Admit failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Wait(ctx)
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Wait = %v, want ErrDrainTimeout", err)
	}
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("Wait returned before the context deadline")
	}
	c.Release()
}

func TestWaitReturnsAfterDrain(t *testing.T) {
	c := New()
	if !c.Admit() {
		t.Fatal("Admit failed")
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Wait returned before Release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	c.Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Release")
	}
}

func TestConcurrentAdmitCloseNeverAdmitsAfterClose(t *testing.T) {
	for i := 0; i < 200; i++ {
		c := New()
		var wg sync.WaitGroup
		admitted := make(chan bool, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			admitted <- c.Admit()
		}()
		c.Close()
		wg.Wait()
		if <-admitted {
			// If Admit won the race, it was admitted before Close; release it.
			c.Release()
		}
		if c.Active() != 0 {
			t.Fatalf("active = %d after drain", c.Active())
		}
	}
}
