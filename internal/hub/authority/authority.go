// Package authority provides the single-process ownership lock for an Agbero
// data directory. The OS lock, not a PID file or socket, is the source of truth.
package authority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
)

// ErrLocked means another process currently owns the data directory.
var ErrLocked = errors.New("authority: data directory is owned by another process")

// Lock is a held OS-level exclusive lock.
type Lock struct {
	file *os.File
	path string
	held bool
}

// Path returns the lock file path.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// TryAcquire makes one attempt to acquire the data-directory ownership lock.
func TryAcquire(dataDir string) (*Lock, error) {
	if dataDir == "" {
		return nil, errors.New("authority: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("authority: create data directory: %w", err)
	}
	path := filepath.Join(dataDir, def.DefaultAuthorityLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, def.FileModePrivate)
	if err != nil {
		return nil, fmt.Errorf("authority: open lock file: %w", err)
	}
	if err := tryLock(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("authority: acquire lock: %w", err)
	}
	return &Lock{file: f, path: path, held: true}, nil
}

// Acquire retries until the lock is available or ctx expires.
func Acquire(ctx context.Context, dataDir string) (*Lock, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		l, err := TryAcquire(dataDir)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, ErrLocked) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrLocked, ctx.Err())
		case <-time.After(def.DefaultAuthorityRetryDelay):
		}
	}
}

// Release unlocks and closes the lock file. It is safe to call more than once.
func (l *Lock) Release() error {
	if l == nil || !l.held {
		return nil
	}
	l.held = false
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
