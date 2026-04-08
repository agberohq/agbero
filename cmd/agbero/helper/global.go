package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

var knownEditors = map[string]bool{
	"vim": true, "vi": true, "nano": true,
	"micro": true, "code": true, "cat": true,
	"less": true, "more": true,
}

func runEditor(editor, filePath string) {
	if !knownEditors[editor] {
		fmt.Printf("unknown editor %q, falling back to cat\n", editor)
		editor = "cat"
	}
	cmd := exec.Command(editor, filePath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to open editor: %v\n", err)
	}
}

// LoadGlobal parses configFile and applies woos defaults.
// Exported so that main() can load the global config before constructing the
// Helper (needed to resolve DataDir for the keeper open call).
func LoadGlobal(configFile string) (*alaye.Global, error) {
	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(configFile)
	woos.DefaultApply(global, abs)
	return global, nil
}

// loadGlobal is the package-internal alias kept for callers inside the helper
// package (configuration.go, host.go, etc.) that already use the unexported name.
func loadGlobal(configFile string) (*alaye.Global, error) {
	return LoadGlobal(configFile)
}
