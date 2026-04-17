package tlss

import (
	"os"
	"os/user"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

func BootstrapEnv(logger *ll.Logger) error {
	changed := false
	if os.Getenv(def.EnvHome) == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			_ = os.Setenv(def.EnvHome, u.HomeDir)
			changed = true
		}
	}
	if os.Getenv(def.EnvUser) == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			_ = os.Setenv(def.EnvUser, u.Username)
			changed = true
		}
	}
	if os.Getenv(def.EnvLogName) == "" && os.Getenv(def.EnvUser) != "" {
		_ = os.Setenv(def.EnvLogName, os.Getenv(def.EnvUser))
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
