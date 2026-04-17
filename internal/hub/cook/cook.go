package cook

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/errors"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/go-git/go-git/v6/plumbing/transport/ssh"
	"github.com/olekukonko/ll"
)

var (
	ErrCloneFailed      = errors.New("git clone failed")
	ErrInvalidCommit    = errors.New("invalid commit hash")
	ErrWorkDirNotSet    = errors.New("work directory not set")
	ErrRepositoryNotSet = errors.New("repository URL not set")
	ErrAuthFailed       = errors.New("authentication failed")
)

// Config defines the configuration for a Cook instance.
type Config struct {
	ID       string
	URL      string // empty for push-only mode
	Branch   string
	WorkDir  string
	Logger   *ll.Logger
	Auth     AuthConfig
	Metrics  *Metrics
	KeepLast int
}

// AuthConfig defines authentication options for git operations.
type AuthConfig struct {
	Type             string // "basic", "ssh-key", "ssh-agent"
	Username         string
	Password         string
	SSHKey           string
	SSHKeyPassphrase string
}

// Metrics tracks deployment statistics.
type Metrics struct {
	DeploymentsTotal   atomic.Int64
	DeploymentErrors   atomic.Int64
	DeploymentDuration atomic.Int64
	LastDeploymentTime atomic.Value
}

// Cook handles atomic git-based deployments with zero downtime.
// In push-only mode (URL == ""), Cook does not clone — it serves
// content written directly to the work directory via webhook.
type Cook struct {
	config   Config
	logger   *ll.Logger
	repoMu   sync.Mutex
	deployMu sync.Mutex

	mu      sync.RWMutex
	current string // commit hash of active deployment; empty in push-only mode

	// pushPath holds the serving directory for push-only mode.
	// Set once by SetCurrentPath and never changed thereafter.
	pushPath string
}

// New creates a Cook instance. URL may be empty for push-only mode,
// in which case Make must never be called.
func New(cfg Config) (*Cook, error) {
	if cfg.ID == "" {
		return nil, errors.New("cook ID is required")
	}
	if cfg.WorkDir == "" {
		return nil, ErrWorkDirNotSet
	}

	// push-only: skip URL requirement and clone setup
	if cfg.URL != "" {
		if cfg.KeepLast <= 0 {
			cfg.KeepLast = 2
		}
		if err := os.MkdirAll(cfg.WorkDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create work directory: %w", err)
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = &ll.Logger{}
	}
	logger = logger.Namespace("cook").AddContext("id", cfg.ID)

	return &Cook{
		config: cfg,
		logger: logger,
	}, nil
}

// SetCurrentPath sets the serving path directly without a deployment.
// Used exclusively by push-only mode so CurrentPath returns immediately
// rather than blocking on a clone that will never happen.
func (c *Cook) SetCurrentPath(path string) {
	c.mu.Lock()
	c.pushPath = path
	c.mu.Unlock()
}

// CurrentPath returns the filesystem path currently being served.
// For pull/both mode this is the most recent deployment directory.
// For push-only mode this is the work directory set by SetCurrentPath.
func (c *Cook) CurrentPath() string {
	c.mu.RLock()
	pushPath := c.pushPath
	current := c.current
	c.mu.RUnlock()

	// push-only mode
	if pushPath != "" {
		return pushPath
	}

	// pull/both mode — check in-memory commit first
	if current != "" {
		path := c.deployPath(current)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// fallback: read from symlink (e.g. after restart)
	linkPath := filepath.Join(c.workDir(), "current")
	target, err := os.Readlink(linkPath)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(c.workDir(), target)
	}
	if _, err := os.Stat(target); err != nil {
		return ""
	}
	return target
}

// CurrentCommit returns the commit hash of the active deployment.
// Returns empty string in push-only mode.
func (c *Cook) CurrentCommit() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Make performs an atomic deployment from the configured repository.
// Must not be called in push-only mode (URL == "").
func (c *Cook) Make(ctx context.Context) error {
	c.repoMu.Lock()
	defer c.repoMu.Unlock()

	c.deployMu.Lock()
	defer c.deployMu.Unlock()

	start := time.Now()
	var deployErr error
	defer func() { c.recordMetrics(start, deployErr) }()

	if err := c.validate(); err != nil {
		deployErr = err
		return err
	}

	deployBase := c.deployBase()
	if err := os.MkdirAll(deployBase, 0750); err != nil {
		deployErr = fmt.Errorf("failed to create deploy base: %w", err)
		return deployErr
	}

	tmpDir, err := os.MkdirTemp(deployBase, "tmp_")
	if err != nil {
		deployErr = fmt.Errorf("failed to create temp directory: %w", err)
		return deployErr
	}
	defer func() {
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	c.logger.Fields("branch", c.config.Branch).Infof("cloning repository %s", c.config.URL)

	cloneOpts := &git.CloneOptions{
		URL:          c.config.URL,
		SingleBranch: true,
		Depth:        1,
		Progress:     io.Discard,
		Auth:         c.getAuth(),
	}
	if c.config.Branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(c.config.Branch)
	}

	repo, err := git.PlainCloneContext(ctx, tmpDir, cloneOpts)
	if err != nil {
		deployErr = fmt.Errorf("%w: %v", ErrCloneFailed, err)
		return deployErr
	}

	ref, err := repo.Head()
	if err != nil {
		deployErr = fmt.Errorf("failed to get HEAD: %w", err)
		return deployErr
	}

	commitHash := ref.Hash().String()
	if len(commitHash) < 8 {
		deployErr = ErrInvalidCommit
		return deployErr
	}

	deployDir := c.deployPath(commitHash)

	if _, err := os.Stat(deployDir); err == nil {
		c.logger.Fields("hash", commitHash).Infof("commit %s already deployed, switching", commitHash[:8])
		_ = os.RemoveAll(tmpDir)
		tmpDir = ""
	} else {
		if err := os.RemoveAll(filepath.Join(tmpDir, ".git")); err != nil {
			c.logger.Warnf("failed to remove .git directory: %v", err)
		}
		if err := os.Rename(tmpDir, deployDir); err != nil {
			deployErr = fmt.Errorf("failed to finalize deployment: %w", err)
			return deployErr
		}
		tmpDir = ""
	}

	if err := c.atomicSwitch(deployDir, commitHash); err != nil {
		deployErr = fmt.Errorf("failed to activate deployment: %w", err)
		return deployErr
	}

	c.logger.Infof("activated commit %s", commitHash[:8])

	c.mu.Lock()
	c.current = commitHash
	c.mu.Unlock()

	go c.cleanupDeployments(commitHash)
	return nil
}

// Rollback switches to a previous deployment by commit hash.
func (c *Cook) Rollback(commitHash string) error {
	c.repoMu.Lock()
	defer c.repoMu.Unlock()

	c.deployMu.Lock()
	defer c.deployMu.Unlock()

	if len(commitHash) < 8 {
		return ErrInvalidCommit
	}

	deployDir := c.deployPath(commitHash)
	if _, err := os.Stat(deployDir); err != nil {
		return fmt.Errorf("deployment %s not found: %w", commitHash, err)
	}

	if err := c.atomicSwitch(deployDir, commitHash); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	c.mu.Lock()
	c.current = commitHash
	c.mu.Unlock()

	c.logger.Infof("rolled back to commit %s", commitHash[:8])
	return nil
}

// ListDeployments returns all available deployment commits sorted newest first.
func (c *Cook) ListDeployments() ([]Deployment, error) {
	deployBase := c.deployBase()
	entries, err := os.ReadDir(deployBase)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var deps []Deployment
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "tmp_") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		deps = append(deps, Deployment{
			Commit:    e.Name(),
			Path:      filepath.Join(deployBase, e.Name()),
			CreatedAt: info.ModTime(),
		})
	}

	for i := 0; i < len(deps)-1; i++ {
		for j := i + 1; j < len(deps); j++ {
			if deps[i].CreatedAt.Before(deps[j].CreatedAt) {
				deps[i], deps[j] = deps[j], deps[i]
			}
		}
	}
	return deps, nil
}

// Cleanup removes old deployments keeping current + specified count.
func (c *Cook) Cleanup(keep int) error {
	current := c.CurrentCommit()
	deployBase := c.deployBase()

	entries, err := os.ReadDir(deployBase)
	if err != nil {
		return err
	}

	type deployInfo struct {
		commit string
		path   string
		time   time.Time
	}

	var items []deployInfo
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "tmp_") || e.Name() == current {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, deployInfo{
			commit: e.Name(),
			path:   filepath.Join(deployBase, e.Name()),
			time:   info.ModTime(),
		})
	}

	if len(items) <= keep {
		return nil
	}

	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].time.After(items[j].time) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	toDelete := len(items) - keep
	for i := range toDelete {
		c.logger.Infof("cleaning up old deployment %s", items[i].commit[:8])
		if err := os.RemoveAll(items[i].path); err != nil {
			c.logger.Warnf("failed to remove %s: %v", items[i].commit[:8], err)
		}
	}
	return nil
}

// CollectMetrics returns a snapshot of current metrics (if configured).
func (c *Cook) CollectMetrics() Metrics {
	if c.config.Metrics == nil {
		return Metrics{}
	}
	return *c.config.Metrics
}

// internal helpers

func (c *Cook) validate() error {
	if c.config.URL == "" {
		return ErrRepositoryNotSet
	}
	if c.config.WorkDir == "" {
		return ErrWorkDirNotSet
	}
	return nil
}

func (c *Cook) workDir() string {
	return c.config.WorkDir
}

func (c *Cook) deployBase() string {
	return filepath.Join(c.workDir(), "deploy")
}

func (c *Cook) deployPath(commit string) string {
	return filepath.Join(c.deployBase(), commit)
}

func (c *Cook) atomicSwitch(deployDir, commitHash string) error {
	linkPath := filepath.Join(c.workDir(), "current")
	tmpLink := linkPath + ".tmp"
	_ = os.Remove(tmpLink)

	relPath, err := filepath.Rel(c.workDir(), deployDir)
	if err != nil {
		relPath = deployDir
	}
	if err := os.Symlink(relPath, tmpLink); err != nil {
		return fmt.Errorf("failed to create temp symlink: %w", err)
	}
	if err := os.Rename(tmpLink, linkPath); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("failed to swap symlink: %w", err)
	}
	return nil
}

func (c *Cook) cleanupDeployments(_ string) {
	_ = c.Cleanup(c.config.KeepLast)
}

func (c *Cook) getAuth() transport.AuthMethod {
	auth := c.config.Auth
	switch auth.Type {
	case "basic":
		if auth.Username != "" {
			return &http.BasicAuth{Username: auth.Username, Password: auth.Password}
		}
	case "ssh-key":
		if auth.SSHKey != "" {
			pk, err := ssh.NewPublicKeys("git", []byte(auth.SSHKey), auth.SSHKeyPassphrase)
			if err != nil {
				c.logger.Warnf("failed to parse SSH key: %v", err)
				return nil
			}
			return pk
		}
	case "ssh-agent":
		am, err := ssh.NewSSHAgentAuth("git")
		if err != nil {
			c.logger.Warnf("failed to connect to SSH agent: %v", err)
			return nil
		}
		return am
	}
	return nil
}

func (c *Cook) recordMetrics(start time.Time, err error) {
	if c.config.Metrics == nil {
		return
	}
	duration := time.Since(start)
	c.config.Metrics.DeploymentsTotal.Add(1)
	c.config.Metrics.DeploymentDuration.Add(duration.Nanoseconds())
	c.config.Metrics.LastDeploymentTime.Store(time.Now())
	if err != nil {
		c.config.Metrics.DeploymentErrors.Add(1)
	}
	c.logger.Fields("duration_ms", duration.Milliseconds(), "error", err != nil).Debug("deployment completed")
}

// Deployment represents a single deployed version.
type Deployment struct {
	Commit    string
	Path      string
	CreatedAt time.Time
}
