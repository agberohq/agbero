package tlss

import (
	"os"
	"os/user"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
)

func BootstrapEnv(logger *ll.Logger) error {
	changed := false
	if os.Getenv(woos.EnvHome) == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			_ = os.Setenv(woos.EnvHome, u.HomeDir)
			changed = true
		}
	}
	if os.Getenv(woos.EnvUser) == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			_ = os.Setenv(woos.EnvUser, u.Username)
			changed = true
		}
	}
	if os.Getenv(woos.EnvLogName) == "" && os.Getenv(woos.EnvUser) != "" {
		_ = os.Setenv(woos.EnvLogName, os.Getenv(woos.EnvUser))
		changed = true
	}
	if logger != nil && changed {
		logger.Debugf("tlss: bootstrapped env (HOME=%q USER=%q LOGNAME=%q)",
			os.Getenv("HOME"), os.Getenv("USER"), os.Getenv("LOGNAME"))
	}
	return nil
}

func IsCARootInstalled(certDir expect.Folder) bool {
	if certDir == "" {
		return false
	}
	return certDir.FileExists("ca-cert.pem")
}
