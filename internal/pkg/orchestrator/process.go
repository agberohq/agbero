package orchestrator

import (
	"context"
	"os"
	"os/exec"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

type Process struct {
	Config alaye.Work
	Logger *ll.Logger
	Env    []string // Resolved env strings: KEY=VAL
}

// Do implements jack.Task
func (p *Process) Do() error {
	return p.Execute(context.Background())
}

func (p *Process) Execute(ctx context.Context) error {
	if len(p.Config.Command) == 0 {
		return nil
	}

	cmd := exec.CommandContext(ctx, p.Config.Command[0], p.Config.Command[1:]...)
	cmd.Env = append(os.Environ(), p.Env...)

	// Pipe logs to Agbero Logger
	cmd.Stdout = p.Logger.Namespace(p.Config.Name).Writer(ll.LevelInfo)
	cmd.Stderr = p.Logger.Namespace(p.Config.Name).Writer(ll.LevelError)

	p.Logger.Infof("starting worker process: %s", p.Config.Name)
	return cmd.Run()
}
