package cook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	URL      string
	Branch   string
	WorkDir  string
	Logger   *ll.Logger
	Auth     AuthConfig // Optional: authentication configuration
	Metrics  *Metrics   // Optional: metrics collection
	KeepLast int        // Number of deployments to keep (default: 2)
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
	DeploymentDuration atomic.Int64 // nanoseconds
	LastDeploymentTime atomic.Value // time.Time
}

// Cook handles atomic git-based deployments with zero downtime.
type Cook struct {
	config   Config
	logger   *ll.Logger
	repoMu   sync.Mutex // Prevents concurrent operations on same repo
	deployMu sync.Mutex // Protects deployment operations

	mu      sync.RWMutex
	current string // commit hash of active deployment
}

// New creates a Cook instance with the provided configuration.
func New(cfg Config) (*Cook, error) {
	if cfg.ID == "" {
		return nil, errors.New("cook ID is required")
	}
	if cfg.URL == "" {
		return nil, ErrRepositoryNotSet
	}
	if cfg.WorkDir == "" {
		return nil, ErrWorkDirNotSet
	}

	// Set defaults
	if cfg.KeepLast <= 0 {
		cfg.KeepLast = 2
	}

	// Ensure work directory exists
	workDir := filepath.Join(cfg.WorkDir, cfg.ID)
	if err := os.MkdirAll(workDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
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

// CurrentPath returns the filesystem path to the currently active deployment.
func (c *Cook) CurrentPath() string {
	c.mu.RLock()
	current := c.current
	c.mu.RUnlock()

	if current != "" {
		path := c.deployPath(current)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fallback: read from symlink
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
func (c *Cook) CurrentCommit() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Make performs an atomic deployment from the configured repository.
func (c *Cook) Make(ctx context.Context) error {
	// Prevent concurrent operations on the same repository
	c.repoMu.Lock()
	defer c.repoMu.Unlock()

	c.deployMu.Lock()
	defer c.deployMu.Unlock()

	start := time.Now()
	var deployErr error
	defer c.recordMetrics(start, deployErr)

	if err := c.validate(); err != nil {
		deployErr = err
		return err
	}

	deployBase := c.deployBase()
	if err := os.MkdirAll(deployBase, 0750); err != nil {
		deployErr = fmt.Errorf("failed to create deploy base: %w", err)
		return deployErr
	}

	// Create temp directory for clone
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

	c.logger.Infof("cloning repository %s (branch: %s)", c.config.URL, c.config.Branch)

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

	// Check if this commit is already deployed
	if _, err := os.Stat(deployDir); err == nil {
		c.logger.Infof("commit %s already deployed, switching", commitHash[:8])
		_ = os.RemoveAll(tmpDir)
		tmpDir = ""
	} else {
		// Remove .git to save space
		gitDir := filepath.Join(tmpDir, ".git")
		if err := os.RemoveAll(gitDir); err != nil {
			c.logger.Warnf("failed to remove .git directory: %v", err)
		}

		// Atomic move from temp to final location
		if err := os.Rename(tmpDir, deployDir); err != nil {
			deployErr = fmt.Errorf("failed to finalize deployment: %w", err)
			return deployErr
		}
		tmpDir = ""
	}

	// Atomic symlink switch for zero-downtime deployment
	if err := c.atomicSwitch(deployDir, commitHash); err != nil {
		deployErr = fmt.Errorf("failed to activate deployment: %w", err)
		return deployErr
	}

	c.logger.Infof("activated commit %s", commitHash[:8])

	// Update in-memory state
	c.mu.Lock()
	c.current = commitHash
	c.mu.Unlock()

	// Cleanup old deployments in background
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

// ListDeployments returns all available deployment commits sorted by time (newest first).
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

	// Sort by time descending (newest first)
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
		if !e.IsDir() || strings.HasPrefix(e.Name(), "tmp_") {
			continue
		}
		if e.Name() == current {
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

	// Sort oldest first
	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].time.After(items[j].time) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	toDelete := len(items) - keep
	for i := 0; i < toDelete; i++ {
		c.logger.Infof("cleaning up old deployment %s", items[i].commit[:8])
		if err := os.RemoveAll(items[i].path); err != nil {
			c.logger.Warnf("failed to remove %s: %v", items[i].commit[:8], err)
		}
	}

	return nil
}

// Metrics returns current metrics snapshot (if configured).
func (c *Cook) Metrics() Metrics {
	if c.config.Metrics == nil {
		return Metrics{}
	}
	return Metrics{
		DeploymentsTotal:   atomic.Int64{},
		DeploymentErrors:   atomic.Int64{},
		DeploymentDuration: atomic.Int64{},
		LastDeploymentTime: atomic.Value{},
	}
}

// validate checks configuration.
func (c *Cook) validate() error {
	if c.config.URL == "" {
		return ErrRepositoryNotSet
	}
	if c.config.WorkDir == "" {
		return ErrWorkDirNotSet
	}
	return nil
}

// workDir returns the full work directory path.
func (c *Cook) workDir() string {
	return filepath.Join(c.config.WorkDir, c.config.ID)
}

// deployBase returns the base directory for all deployments.
func (c *Cook) deployBase() string {
	return filepath.Join(c.workDir(), "deploy")
}

// deployPath returns the path for a specific commit deployment.
func (c *Cook) deployPath(commit string) string {
	return filepath.Join(c.deployBase(), commit)
}

// atomicSwitch performs an atomic symlink switch.
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

// cleanupDeployments removes old deployments.
func (c *Cook) cleanupDeployments(currentCommit string) {
	_ = c.Cleanup(c.config.KeepLast)
}

// getAuth returns transport.AuthMethod based on configuration.
func (c *Cook) getAuth() transport.AuthMethod {
	auth := c.config.Auth

	switch auth.Type {
	case "basic":
		if auth.Username != "" {
			return &http.BasicAuth{
				Username: auth.Username,
				Password: auth.Password,
			}
		}
	case "ssh-key":
		if auth.SSHKey != "" {
			publicKey, err := ssh.NewPublicKeys("git", []byte(auth.SSHKey), auth.SSHKeyPassphrase)
			if err != nil {
				c.logger.Warnf("failed to parse SSH key: %v", err)
				return nil
			}
			return publicKey
		}
	case "ssh-agent":
		// Use SSH agent authentication
		authMethod, err := ssh.NewSSHAgentAuth("git")
		if err != nil {
			c.logger.Warnf("failed to connect to SSH agent: %v", err)
			return nil
		}
		return authMethod
	}

	return nil
}

// recordMetrics updates metrics if configured.
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

	c.logger.Fields(
		"duration_ms", duration.Milliseconds(),
		"error", err != nil,
	).Debug("deployment completed")
}

// Deployment represents a single deployed version.
type Deployment struct {
	Commit    string
	Path      string
	CreatedAt time.Time
}
