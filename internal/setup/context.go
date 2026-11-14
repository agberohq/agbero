package setup

import (
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/agberohq/agbero/internal/core/def"
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
	// A character device is not necessarily a terminal: systemd gives
	// services stdin=/dev/null, which is a character device. Use a real TTY
	// check so a service never enters an interactive prompt.
	interactive := term.IsTerminal(int(os.Stdin.Fd()))

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
	if runtime.GOOS == def.Windows {
		return false
	}
	return os.Geteuid() == 0
}
