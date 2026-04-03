package setup

import (
	"os"
	"runtime"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
)

type Context struct {
	Logger      *ll.Logger
	Interactive bool
	Paths       woos.RuntimePaths
	IsRoot      bool
	Keeper      *keeper.Keeper
	TLSStore    tlsstore.Store
}

func NewContext(logger *ll.Logger) *Context {
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

	return &Context{
		Logger:      logger,
		Interactive: interactive,
		Paths:       paths,
		IsRoot:      isRoot,
	}
}

func (c *Context) SetKeeper(store *keeper.Keeper) {
	c.Keeper = store
}

func (c *Context) SetTLSStore(store tlsstore.Store) {
	c.TLSStore = store
}

func checkIsRoot() bool {
	if runtime.GOOS == woos.Windows {
		return false
	}
	return os.Geteuid() == 0
}
