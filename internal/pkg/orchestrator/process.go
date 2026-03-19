package orchestrator

import (
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
)

// Process encapsulates the state and logic required to execute an external command.
// It manages environment variables, working directories, and log redirection to Agbero's logger.
type Process struct {
	Config alaye.Work
	Env    []string
	Dir    string
	Logger *ll.Logger
}

// Do executes the process without specific input or output redirection, primarily for background tasks.
// It uses a background context and is compatible with jack's Task interface for loopers.
func (p *Process) Do() error {
	return p.Run(context.Background(), nil, nil)
}

// Run configures and starts the external process using the provided context and pipes.
// It connects Stdin to the provided reader and Stdout to the writer, streaming logs to the internal logger.
func (p *Process) Run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if len(p.Config.Command) == 0 {
		return nil
	}

	// Ensure working directory exists before execution
	if p.Dir != "" {
		if err := os.MkdirAll(p.Dir, 0755); err != nil {
			return err
		}
	}

	cmd := exec.CommandContext(ctx, p.Config.Command[0], p.Config.Command[1:]...)
	cmd.Dir = p.Dir
	cmd.Env = p.Env

	if stdin != nil {
		cmd.Stdin = stdin
	}

	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = p.Logger.Writer(lx.LevelInfo)
	}

	cmd.Stderr = p.Logger.Writer(lx.LevelError)

	return cmd.Run()
}
