//go:build !windows

package anchor

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func endpointPath(dir, name string) string {
	path := filepath.Join(dir, name+".sock")
	if len(path) <= 100 {
		return path
	}
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(os.TempDir(), fmt.Sprintf("agbero-anchor-%x.sock", sum[:8]))
}

func listenEndpoint(path string) (net.Listener, error) { return net.Listen("unix", path) }

func dialEndpoint(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

func secureEndpoint(path string)  { _ = os.Chmod(path, 0600) }
func cleanupEndpoint(path string) { _ = os.Remove(path) }
