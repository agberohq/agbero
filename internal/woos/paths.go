package woos

import (
	"os"
	"path/filepath"
)

type RuntimePaths struct {
	BaseDir    string // e.g. /etc/agbero or C:\ProgramData\agbero
	ConfigFile string
	HostsDir   string
	CertsDir   string
}

// GetUserDefaults returns defaults for the current user (~/.config/agbero)
func GetUserDefaults() (RuntimePaths, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return RuntimePaths{}, err
	}

	base := filepath.Join(configDir, Name)
	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: filepath.Join(base, DefaultConfigName),
		HostsDir:   filepath.Join(base, HostDir.Name()),
		CertsDir:   filepath.Join(base, CertDir.Name()),
	}, nil
}

// ResolveRelative  ensures a directory is absolute relative to the config file location
func ResolveRelative(configPath, targetDir string) string {
	if filepath.IsAbs(targetDir) {
		return targetDir
	}
	return filepath.Join(filepath.Dir(configPath), targetDir)
}

// EnsureDir is a helper to centralize Mkdir logic
func EnsureDir(path string, secure bool) error {
	perm := os.FileMode(DirPerm)
	if secure {
		perm = SecurePerm
	}
	return os.MkdirAll(path, perm)
}
