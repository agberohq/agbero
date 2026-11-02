//go:build !windows

package helper

import (
	"os"
	"os/signal"
	"syscall"
)

// registerReload installs a SIGHUP handler that reloads the live server config.
// It returns a stop function; the signal loop exits when the server shuts down,
// so a SIGHUP arriving after Start() returns cannot touch a dead server.
func registerReload(reload func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				reload()
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
}
