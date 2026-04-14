package orchestrator

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
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
	maxWorkerNameLen    = 64
)

// Config holds all construction-time configuration for a Manager.
// AllowedCommands comes from alaye.Security and must be explicitly set
// by the operator — an empty list means no workers are permitted to run.
type Config struct {
	Logger *ll.Logger

	WorkDir expect.Folder

	// CookMgr is optional; when non-nil git-backed routes use it for
	// path resolution.
	CookMgr *cook.Manager

	GlobalEnv map[string]expect.Value

	// AllowedCommands is the authoritative allowlist of bare executable
	// names (no path, no extension). Comes from alaye.Security.AllowedCommands.
	// Empty = nothing is permitted to execute.
	AllowedCommands []string

	// PoolSize overrides the default worker-pool size. <= 0 uses defaultPoolSize.
	PoolSize int

	// DropPrivileges controls whether worker processes are started under
	// uid/gid 65534 (nobody). Requires the parent process to be root.
	DropPrivileges bool
}

// Manager orchestrates worker processes on behalf of one or more routes.
type Manager struct {
	pool            *jack.Pool
	loopers         *mappo.Concurrent[string, *jack.Looper]
	logger          *ll.Logger
	workDir         expect.Folder
	cookMgr         *cook.Manager
	globalEnv       map[string]expect.Value
	allowedCommands map[string]bool
	dropPrivileges  bool

	// runOnceWg tracks in-flight RunOnce submissions so callers can
	// synchronise without tearing down the pool.
	runOnceWg sync.WaitGroup
}

// New constructs a Manager from the supplied Config.
// The allowlist is built strictly from Config.AllowedCommands — no implicit
// defaults are added. An empty slice means no commands are permitted.
func New(cfg Config) *Manager {
	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = defaultPoolSize
	}

	allowed := make(map[string]bool, len(cfg.AllowedCommands))
	for _, cmd := range cfg.AllowedCommands {
		allowed[cmd] = true
	}

	return &Manager{
		pool:            jack.NewPool(poolSize),
		loopers:         mappo.NewConcurrent[string, *jack.Looper](),
		logger:          cfg.Logger.Namespace("orchestrator"),
		workDir:         cfg.WorkDir,
		cookMgr:         cfg.CookMgr,
		globalEnv:       cfg.GlobalEnv,
		allowedCommands: allowed,
		dropPrivileges:  cfg.DropPrivileges,
	}
}

// Provision registers and starts all workers declared in route for the
// given host. RunOnce workers are submitted to the pool; Background
// workers get a supervised looper.
func (m *Manager) Provision(host string, route alaye.Route) error {
	safeHost, err := sanitizeHostName(host)
	if err != nil {
		return fmt.Errorf("invalid host name: %w", err)
	}

	for _, w := range route.Serverless.Workers {
		if err := validateWorkerConfig(w); err != nil {
			return fmt.Errorf("invalid worker %s: %w", w.Name, err)
		}

		dir := m.ResolveDir(safeHost, route, w)
		env := expect.CompileEnv(m.globalEnv, route.Env, w.Env)

		proc := m.NewProcess(w, env, dir,
			m.logger.Namespace(safeHost).Namespace(w.Name),
		)

		if w.RunOnce {
			m.logger.Fields("worker", w.Name, "mode", "run_once").Info("submitting worker")
			m.runOnceWg.Add(1)

			if err := m.pool.Submit(jack.Func(func() error {
				defer m.runOnceWg.Done()
				if err := proc.Do(); err != nil {
					proc.Logger.Fields("error", err).Error("worker failed")
					return err
				}
				return nil
			})); err != nil {
				m.runOnceWg.Done()
				return fmt.Errorf("submit worker: %w", err)
			}
			continue
		}

		if w.Background {
			m.startLooper(w.Name, proc)
		}
	}
	return nil
}

// WaitRunOnce blocks until every RunOnce task submitted via Provision
// has finished executing. It does not shut down the pool.
func (m *Manager) WaitRunOnce() {
	m.runOnceWg.Wait()
}

// IsAllowed reports whether the bare executable name is permitted.
// This is the single authority — WorkerHandler and any other call site
// must use this rather than inspecting the allowlist directly.
func (m *Manager) IsAllowed(cmd string) bool {
	return m.allowedCommands[cmd]
}

// NewProcess constructs a Process correctly wired to this manager's allowlist
// and privilege settings. WorkerHandler and other call sites must use this
// instead of constructing Process directly — it ensures the allowlist is
// never missing at the point of execution.
func (m *Manager) NewProcess(cfg alaye.Work, env []string, dir string, logger *ll.Logger) *Process {
	return &Process{
		Config:          cfg,
		Env:             env,
		Dir:             dir,
		Logger:          logger,
		AllowedCommands: m.allowedCommands,
		DropPrivileges:  m.dropPrivileges,
	}
}

// ResolveDir determines the working directory for a worker.
// ResolveDir determines the working directory for a worker.
//
// Resolution order:
// serverless.git — if the serverless block has its own git config and the
//
//	cook manager has a deployed checkout, use that. Serverless git is
//	intentionally separate from web.git so that executed scripts are never
//	co-located with publicly served files.
//
// serverless.root — an explicit absolute or relative path set by the
//
//	operator. Relative paths are anchored to workDir. The resolved path is
//	validated to stay within workDir to prevent traversal.
//
// workDir default — a per-host, per-worker subdirectory under workDir.
func (m *Manager) ResolveDir(host string, r alaye.Route, w alaye.Work) string {
	// Serverless-own git checkout — never web.git.
	if r.Serverless.Git.Enabled.Active() && m.cookMgr != nil {
		return m.cookMgr.CurrentPath(r.Serverless.Git.ID)
	}

	// Explicit root declared in the serverless block.
	if r.Serverless.Root != "" {
		cleaned := filepath.Clean(r.Serverless.Root)
		if !strings.HasPrefix(cleaned, "/") {
			// Relative — anchor to workDir.
			cleaned = filepath.Join(m.workDir.String(), cleaned)
		}
		// Validate it stays within workDir to prevent traversal.
		base := filepath.Clean(m.workDir.String())
		if !strings.HasPrefix(cleaned, base+string(filepath.Separator)) && cleaned != base {
			m.logger.Fields("worker", w.Name, "root", r.Serverless.Root).
				Error("serverless root escapes workDir, falling back to default")
			// Fall through to safe default rather than returning a bad path.
		} else {
			return cleaned
		}
	}

	// Safe per-host/per-worker default.
	safeName := sanitizeName(w.Name)
	return m.workDir.FilePath(workerSubDir, host, safeName)
}

func (m *Manager) startLooper(name string, proc *Process) {
	safeName := sanitizeName(name)

	looper, loaded := m.loopers.LoadOrStore(safeName, jack.NewLooper(proc.Do,
		jack.WithLooperName(safeName),
		jack.WithLooperInterval(defaultRestartDelay),
		jack.WithLooperBackoff(proc.Config.Restart != "no"),
	))

	if !loaded {
		m.logger.Fields("worker", safeName, "mode", "background").Info("starting background worker")
		looper.Start()
	}
}

// Stop halts all background loopers.
func (m *Manager) Stop() {
	m.loopers.Range(func(name string, l *jack.Looper) bool {
		m.logger.Fields("worker", name).Info("stopping worker")
		l.Stop()
		return true
	})
	m.loopers.Clear()
}

// AllowedCommands returns a copy of the effective allowlist for introspection.
func (m *Manager) AllowedCommands() map[string]bool {
	out := make(map[string]bool, len(m.allowedCommands))
	for k, v := range m.allowedCommands {
		out[k] = v
	}
	return out
}

// helpers

func sanitizeHostName(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if len(host) > 255 {
		return "", fmt.Errorf("host too long")
	}

	cleaned := strings.ToLower(host)

	for _, c := range cleaned {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_') {
			return "", fmt.Errorf("invalid character in host: %c", c)
		}
	}

	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal attempt")
	}

	return cleaned, nil
}

func validateWorkerConfig(w alaye.Work) error {
	if w.Name == "" {
		return fmt.Errorf("name required")
	}
	if len(w.Name) > maxWorkerNameLen {
		return fmt.Errorf("name too long (max %d)", maxWorkerNameLen)
	}
	if len(w.Command) == 0 {
		return fmt.Errorf("command required")
	}

	clean := sanitizeName(w.Name)
	if clean != w.Name {
		return fmt.Errorf("name contains invalid characters")
	}

	return nil
}
