package authority

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
)

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first, err := TryAcquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()

	if _, err := TryAcquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire = %v, want ErrLocked", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := TryAcquire(dir)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	second.Release()
}

func TestAcquireRetriesUntilRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := TryAcquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		l, err := Acquire(ctx, dir)
		if err == nil {
			l.Release()
		}
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	first.Release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAcquireOnlyOneWins(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := TryAcquire(dir)
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				l.Release()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d, want 1", wins)
	}
}

func TestLockPath(t *testing.T) {
	l, err := TryAcquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if filepath.Base(l.Path()) != def.DefaultAuthorityLockName {
		t.Fatalf("lock path = %q", l.Path())
	}
}
