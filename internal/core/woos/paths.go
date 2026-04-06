package woos

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/agberohq/agbero/internal/core/expect"
)

type RuntimePaths struct {
	BaseDir    expect.Folder `json:"base_dir"`
	ConfigFile string        `json:"config_file"`
	HostsDir   expect.Folder `json:"hosts_dir"`
	CertsDir   expect.Folder `json:"certs_dir"`
	DataDir    expect.Folder `json:"data_dir"`
	LogsDir    expect.Folder `json:"logs_dir"`
	WorkDir    expect.Folder `json:"work_dir"`
}

// GetUserDefaults returns defaults for the current user (~/.config/agbero)
// It respects the AGBERO_HOME environment variable if set.
func GetUserDefaults() (RuntimePaths, error) {
	var baseDir string

	if custom := os.Getenv("AGBERO_HOME"); custom != "" {
		baseDir = custom
	} else {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return RuntimePaths{}, err
		}
		baseDir = filepath.Join(configDir, Name)
	}

	base := expect.NewFolder(baseDir)

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: base.FilePath(DefaultConfigName),
		HostsDir:   base.Sub(HostDir),
		CertsDir:   base.Sub(CertDir),
		DataDir:    base.Sub(DataDir),
		LogsDir:    base.Sub(LogDir),
		WorkDir:    base.Sub(WorkDir),
	}, nil
}

// DefaultPaths returns the OS-specific default paths for system-wide installation.
// It respects the AGBERO_HOME environment variable if set.
func DefaultPaths() RuntimePaths {
	var path string

	if custom := os.Getenv("AGBERO_HOME"); custom != "" {
		path = custom
	} else {
		if runtime.GOOS == Windows || os.PathSeparator == WindowBackSlash {
			path = filepath.Join(os.Getenv(ENVProgramData), Name)
		} else {
			path = filepath.Join(ETCPath, Name)
		}
	}

	base := expect.NewFolder(path)

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: base.FilePath(DefaultConfigName),
		HostsDir:   base.Sub(HostDir),
		CertsDir:   base.Sub(CertDir),
		DataDir:    base.Sub(DataDir),
		LogsDir:    base.Sub(LogDir),
		WorkDir:    base.Sub(WorkDir),
	}
}
