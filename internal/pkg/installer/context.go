package installer

import (
	"os"
	"runtime"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
)

type Context struct {
	Logger      *ll.Logger
	Interactive bool
	Paths       woos.RuntimePaths
	Env         string // "local" or "prod"
	IsRoot      bool
}

// NewContext creates a shared state for all installers. It determines if
// the current execution is interactive (TTY) or headless (CI/CD/Scripts).
func NewContext(logger *ll.Logger, forceEnv string) *Context {
	interactive := false
	if fileInfo, err := os.Stdin.Stat(); err == nil {
		if (fileInfo.Mode() & os.ModeCharDevice) != 0 {
			interactive = true
		}
	}

	if os.Getenv("CI") == "true" || os.Getenv("AGBERO_HEADLESS") == "1" {
		interactive = false
	}

	isRoot := checkIsRoot()

	var paths woos.RuntimePaths
	if isRoot {
		paths = woos.DefaultPaths()
	} else {
		userPaths, err := woos.GetUserDefaults()
		if err == nil {
			paths = userPaths
		} else {
			paths = woos.DefaultPaths()
		}
	}

	env := "local"
	if forceEnv != "" {
		env = forceEnv
	} else if isRoot && interactive {
		env = "prod"
	}

	return &Context{
		Logger:      logger,
		Interactive: interactive,
		Paths:       paths,
		Env:         env,
		IsRoot:      isRoot,
	}
}

func checkIsRoot() bool {
	if runtime.GOOS == woos.Windows {
		// Windows root detection requires specialized API calls.
		// For CLI purposes, we assume standard privileges unless overridden.
		return false
	}
	return os.Geteuid() == 0
}
