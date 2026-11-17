//go:build !windows

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
)

// SocketPath returns a short, stable Unix-domain socket path. Unix socket
// paths are limited to roughly 104 bytes on macOS.
func SocketPath(dataDir string) string {
	normal := filepath.Join(dataDir, def.DefaultControlSocketName)
	if len(normal) < def.DefaultControlPathMax {
		return normal
	}
	sum := sha256.Sum256([]byte(dataDir))
	name := "agbero-" + hex.EncodeToString(sum[:8]) + ".sock"
	return filepath.Join(os.TempDir(), name)
}

func prepareControlPath(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0700)
}

func listenControl(path string) (net.Listener, error) { return net.Listen("unix", path) }

func dialControl(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

func secureControlPath(path string) error { return os.Chmod(path, def.FileModePrivate) }
func removeControlPath(path string) error { return os.Remove(path) }
