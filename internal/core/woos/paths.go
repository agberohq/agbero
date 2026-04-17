package woos

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/agberohq/agbero/internal/core/def"
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
		baseDir = filepath.Join(configDir, def.Name)
	}

	base := expect.NewFolder(baseDir)

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: base.FilePath(def.DefaultConfigName),
		HostsDir:   base.Sub(def.HostDir),
		CertsDir:   base.Sub(def.CertDir),
		DataDir:    base.Sub(def.DataDir),
		LogsDir:    base.Sub(def.LogDir),
		WorkDir:    base.Sub(def.WorkDir),
	}, nil
}

// DefaultPaths returns the OS-specific default paths for system-wide installation.
// It respects the AGBERO_HOME environment variable if set.
func DefaultPaths() RuntimePaths {
	var path string

	if custom := os.Getenv("AGBERO_HOME"); custom != "" {
		path = custom
	} else {
		if runtime.GOOS == def.Windows || os.PathSeparator == def.WindowBackSlash {
			path = filepath.Join(os.Getenv(def.ENVProgramData), def.Name)
		} else {
			path = filepath.Join(def.ETCPath, def.Name)
		}
	}

	base := expect.NewFolder(path)

	return RuntimePaths{
		BaseDir:    base,
		ConfigFile: base.FilePath(def.DefaultConfigName),
		HostsDir:   base.Sub(def.HostDir),
		CertsDir:   base.Sub(def.CertDir),
		DataDir:    base.Sub(def.DataDir),
		LogsDir:    base.Sub(def.LogDir),
		WorkDir:    base.Sub(def.WorkDir),
	}
}
