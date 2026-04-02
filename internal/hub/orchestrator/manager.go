// Package orchestrator manages the lifecycle and execution of serverless processes.
// It handles directory resolution, environment compilation, and process monitoring.
package orchestrator

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/cook"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

const (
	defaultRestartDelay = 5 * time.Second
	workerSubDir        = "workers"
	defaultPoolSize     = 10
)

type Manager struct {
	pool      *jack.Pool
	loopers   *mappo.Concurrent[string, *jack.Looper]
	logger    *ll.Logger
	workDir   string
	cookMgr   *cook.Manager
	globalEnv map[string]expect.Value
}

// New constructs a new orchestrator Manager to handle background and ephemeral processes.
// It requires a logger, working directory, and a reference to the cook manager for git-based roots.
func New(logger *ll.Logger, workDir string, cookMgr *cook.Manager, globalEnv map[string]expect.Value) *Manager {
	return &Manager{
		pool:      jack.NewPool(defaultPoolSize),
		loopers:   mappo.NewConcurrent[string, *jack.Looper](),
		logger:    logger.Namespace("orchestrator"),
		workDir:   workDir,
		cookMgr:   cookMgr,
		globalEnv: globalEnv,
	}
}

// Provision sets up and starts workers defined in a route configuration.
// It distinguishes between one-shot tasks and long-running background processes.
func (m *Manager) Provision(host string, route alaye.Route) error {
	for _, w := range route.Serverless.Workers {
		dir := m.ResolveDir(host, route, w)
		env := expect.CompileEnv(m.globalEnv, route.Env, w.Env)

		proc := &Process{
			Config: w,
			Env:    env,
			Dir:    dir,
			Logger: m.logger.Namespace(host).Namespace(w.Name),
		}

		if w.RunOnce {
			if err := proc.Do(); err != nil {
				return fmt.Errorf("worker %s failed: %w", w.Name, err)
			}
			continue
		}

		if w.Background {
			m.startLooper(w.Name, proc)
		}
	}
	return nil
}

// ResolveDir determines the filesystem path where a worker process should execute.
// It prioritizes serverless roots, then git-managed paths, and finally the local work directory.
func (m *Manager) ResolveDir(host string, r alaye.Route, w alaye.Work) string {
	if r.Serverless.Root != "" {
		return r.Serverless.Root
	}

	if r.Web.Git.Enabled.Active() && m.cookMgr != nil {
		return m.cookMgr.CurrentPath(r.Web.Git.ID)
	}

	return filepath.Join(m.workDir, workerSubDir, host, w.Name)
}

// startLooper initiates a managed loop for background worker processes.
// It handles automatic restarts and process supervision via the looper component.
func (m *Manager) startLooper(name string, proc *Process) {
	if _, exists := m.loopers.Get(name); exists {
		return
	}

	looper := jack.NewLooper(proc.Do,
		jack.WithLooperName(name),
		jack.WithLooperInterval(defaultRestartDelay),
		jack.WithLooperBackoff(proc.Config.Restart != "no"),
	)

	m.loopers.Set(name, looper)
	looper.Start()
}

// Stop gracefully shuts down all active loopers and terminates supervised processes.
// It ensures that no background workers are left running after the server closes.
func (m *Manager) Stop() {
	m.loopers.Range(func(name string, l *jack.Looper) bool {
		l.Stop()
		return true
	})
	m.loopers.Clear()
}
