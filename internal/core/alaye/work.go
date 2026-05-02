package alaye

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
)

// Work defines a managed external OS process that acts as a handler or sidecar.
// It handles process execution, environment merging, and lifecycle management via jack.
type Work struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Landlock expect.Toggle `hcl:"landlock,attr" json:"landlock"`

	Name string `hcl:"name,label" json:"name"`

	Engine string `hcl:"engine,attr" json:"engine"`

	Command []string `hcl:"command,attr" json:"command"`

	Env map[string]expect.Value `hcl:"env,attr" json:"env"`

	Background bool `hcl:"background,attr" json:"background"`

	Restart string `hcl:"restart,attr" json:"restart"`

	RunOnce bool `hcl:"run_once,attr" json:"run_once"`

	Schedule string `hcl:"schedule,attr" json:"schedule"`

	Timeout expect.Duration `hcl:"timeout,attr" json:"timeout"`

	Cache Cache `hcl:"cache,block" json:"cache"`
}

// Validate ensures the work block has a name and an executable command.
// It also verifies the configuration of any attached caching logic.
func (w *Work) Validate() error {
	if w.Name == "" {
		return fmt.Errorf("worker name is required")
	}
	if len(w.Command) == 0 {
		return fmt.Errorf("worker %s: command is required", w.Name)
	}
	// Enforce bare command names — no path separators allowed. This mirrors
	// the runtime check in Process.Run and catches misconfiguration early,
	// before any process is ever started.
	cmd := w.Command[0]
	if strings.ContainsRune(cmd, filepath.Separator) {
		return fmt.Errorf("worker %s: command %q must be a bare executable name (no path separators)", w.Name, cmd)
	}
	return w.Cache.Validate()
}
