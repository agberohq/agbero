//go:build windows

package anchor

import (
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/Microsoft/go-winio"
)

func endpointPath(dir, name string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dir) + "/" + name))
	return fmt.Sprintf(`\\.\pipe\agbero-anchor-%x`, sum[:8])
}

func listenEndpoint(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		// Allow the owning user and system; avoid a world-writable pipe.
		SecurityDescriptor: "D:P(A;;GA;;;OW)(A;;GA;;;SY)",
	})
}

func dialEndpoint(path string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(path, &timeout)
}

func secureEndpoint(string)  {}
func cleanupEndpoint(string) {}
