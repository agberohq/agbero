package woos

import (
	"os"
	"path/filepath"
	"runtime"
)

type RuntimePaths struct {
	BaseDir    Folder `json:"base_dir"`
	ConfigFile string `json:"config_file"` // File paths remain strings usually, or specific File type
	HostsDir   Folder `json:"hosts_dir"`
	CertsDir   Folder `json:"certs_dir"`
	DataDir    Folder `json:"data_dir"`
}

// GetUserDefaults returns defaults for the current user (~/.config/agbero)
func GetUserDefaults() (RuntimePaths, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return RuntimePaths{}, err
	}

	base := NewFolder(filepath.Join(configDir, Name))

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: filepath.Join(base.Path(), DefaultConfigName),
		HostsDir:   base.Join(HostDir.Name()),
		CertsDir:   base.Join(CertDir.Name()),
		DataDir:    base.Join(DataDir.Name()),
	}, nil
}

// DefaultPaths returns the OS-specific default paths.
func DefaultPaths() RuntimePaths {
	// Logic moved from cmd/helpers.go and default.go to here
	var base string
	// Simplified OS check logic
	if runtime.GOOS == Windows || os.PathSeparator == WindowBackSlash { // Windows detection via separator or runtime.GOOS
		base = filepath.Join(os.Getenv(ENVProgramData), Name)
	} else {
		base = filepath.Join(ETCPath, Name)
	}

	baseFolder := NewFolder(base)

	return RuntimePaths{
		BaseDir:    baseFolder,
		ConfigFile: filepath.Join(base, DefaultConfigName),
		HostsDir:   baseFolder.Join(HostDir.Name()),
		CertsDir:   baseFolder.Join(CertDir.Name()),
		DataDir:    baseFolder.Join(DataDir.Name()),
	}
}
