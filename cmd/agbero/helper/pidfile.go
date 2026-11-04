package helper

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
)

// writePIDFile atomically records the current process id in dataDir/agbero.pid.
// It returns the path so the caller can remove it on shutdown.
func writePIDFile(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", nil
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}

	path := filepath.Join(dataDir, def.DefaultPIDName)
	tmp := path + ".tmp"
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, []byte(pid), def.ConfigFilePerm); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// removePIDFile removes path only when it still belongs to this process.
// That prevents a shutting-down process from deleting a replacement's pid
// file after a restart race.
func removePIDFile(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid != os.Getpid() {
		return
	}
	_ = os.Remove(path)
}
