//go:build !windows

package helper

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestRegisterReloadHandlesSIGHUP(t *testing.T) {
	called := make(chan struct{}, 1)
	stop := registerReload(func() {
		select {
		case called <- struct{}{}:
		default:
		}
	})
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("SIGHUP did not invoke the reload callback")
	}
}
