package woos

import (
	"os"
	"path/filepath"
	"runtime"
)

// Standardize permissions here
const (
	DirPerm    = 0755
	FilePerm   = 0644
	SecurePerm = 0700 // For keys/certs
)

// Default Names (Relative)
const (
	DefaultConfigName  = "config.hcl"
	DefaultHostDirName = "hosts.d"
	DefaultCertDirName = "certs.d"
	DefaultDataDirName = "data" // For TLS storage if not specified
)

// RuntimePaths holds the calculated absolute paths for the application
type RuntimePaths struct {
	BaseDir    string // e.g. /etc/agbero or C:\ProgramData\agbero
	ConfigFile string
	HostsDir   string
	CertsDir   string
	TLSStorage string
}

// GetSystemDefaults returns the OS-specific default paths.
// This replaces the logic currently in helpers.go
func GetSystemDefaults() RuntimePaths {
	var base string
	if runtime.GOOS == "windows" {
		base = filepath.Join(os.Getenv("ProgramData"), Name)
	} else {
		base = filepath.Join("/etc", Name)
	}

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: filepath.Join(base, DefaultConfigName),
		HostsDir:   filepath.Join(base, DefaultHostDirName),
		CertsDir:   filepath.Join(base, DefaultCertDirName),
		TLSStorage: filepath.Join(base, DefaultDataDirName),
	}
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
		HostsDir:   filepath.Join(base, DefaultHostDirName),
		CertsDir:   filepath.Join(base, DefaultCertDirName),
		TLSStorage: filepath.Join(base, DefaultDataDirName),
	}, nil
}

// ResolveAbs ensures a directory is absolute relative to the config file location
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
