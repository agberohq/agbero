//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package authority

import (
	"errors"
	"os"
)

func tryLock(*os.File) error    { return errors.New("authority: unsupported platform") }
func unlockFile(*os.File) error { return nil }
