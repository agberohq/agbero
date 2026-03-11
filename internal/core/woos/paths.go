package woos

import (
	"os"
	"path/filepath"
	"runtime"
)

type RuntimePaths struct {
	BaseDir    Folder `json:"base_dir"`
	ConfigFile string `json:"config_file"`
	HostsDir   Folder `json:"hosts_dir"`
	CertsDir   Folder `json:"certs_dir"`
	DataDir    Folder `json:"data_dir"`
	LogsDir    Folder `json:"logs_dir"`
	WorkDir    Folder `json:"work_dir"`
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
		LogsDir:    base.Join(LogDir.Name()),
		WorkDir:    base.Join(WorkDir.Name()),
	}, nil
}

// DefaultPaths returns the OS-specific default paths.
func DefaultPaths() RuntimePaths {
	var base string
	if runtime.GOOS == Windows || os.PathSeparator == WindowBackSlash {
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
		LogsDir:    baseFolder.Join(LogDir.Name()),
		WorkDir:    baseFolder.Join(WorkDir.Name()),
	}
}
