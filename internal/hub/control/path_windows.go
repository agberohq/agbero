//go:build windows

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// SocketPath returns a named-pipe path for Windows. Named pipes are not
// limited by filesystem path length and do not create files in the data dir.
func SocketPath(dataDir string) string {
	sum := sha256.Sum256([]byte(dataDir))
	return `\\.\pipe\agbero-` + hex.EncodeToString(sum[:8])
}

func prepareControlPath(string) error { return nil }

func listenControl(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;OW)",
	})
}

func dialControl(path string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(path, &timeout)
}

func secureControlPath(string) error { return nil }
func removeControlPath(string) error { return nil }
