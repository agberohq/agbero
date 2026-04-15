package cook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

const (
	defaultWebhookTimeout = 5 * time.Minute
	maxWebhookBodySize    = 1 << 20
	defaultWorkDirPerm    = 0750
	defaultStopTimeout    = 30 * time.Second
)

// WebhookPayload is the subset of a GitHub/GitLab push payload that agbero uses.
type WebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

// ManagerConfig holds construction-time configuration for the Manager.
type ManagerConfig struct {
	WorkDir expect.Folder
	Pool    *jack.Pool
	Logger  *ll.Logger
}

// Manager owns all registered git integrations and routes webhook requests.
type Manager struct {
	entries *mappo.Concurrent[string, *Entry]
	logger  *ll.Logger
	workDir string
	pool    *jack.Pool
	wg      sync.WaitGroup
}

// Entry holds a running git integration and its cancellation handle.
type Entry struct {
	Cook   *Cook
	Config alaye.Git
	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager constructs a Manager. Both WorkDir and Pool are required.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.WorkDir == "" {
		return nil, errors.New("work directory is required")
	}
	if cfg.Pool == nil {
		return nil, errors.New("worker pool is required")
	}
	if err := cfg.WorkDir.Init(defaultWorkDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create manager workdir: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = ll.New("cookmgr").Disable()
	} else {
		logger = logger.Namespace("cookmgr")
	}
	return &Manager{
		entries: mappo.NewConcurrent[string, *Entry](),
		logger:  logger,
		workDir: cfg.WorkDir.Path(),
		pool:    cfg.Pool,
	}, nil
}

// Register adds or updates a git integration.
//
// Mode is determined by the Git config:
//   - URL set, interval set           → pull (poll only)
//   - URL set, secret set             → push (webhook triggers Make)
//   - URL set, both interval + secret → both (poll + webhook)
//   - URL empty, secret set           → push-only (no clone; webhook writes content)
func (m *Manager) Register(routeKey string, cfg alaye.Git) error {
	if cfg.URL == "" {
		return m.registerPushOnly(routeKey, cfg)
	}

	if existing, ok := m.entries.Get(routeKey); ok {
		unchanged := existing.Config.URL == cfg.URL &&
			existing.Config.Branch == cfg.Branch &&
			existing.Config.WorkDir == cfg.WorkDir &&
			existing.Config.Interval == cfg.Interval &&
			existing.Config.Secret == cfg.Secret &&
			existing.Config.Auth.Type == cfg.Auth.Type &&
			existing.Config.Auth.Username == cfg.Auth.Username
		if unchanged {
			m.logger.Fields("route_key", routeKey).Debug("git integration already configured, skipping")
			return nil
		}
		m.logger.Fields("route_key", routeKey).Info("git integration configuration changed, reloading")
		if existing.cancel != nil {
			existing.cancel()
		}
	}

	targetWorkDir := filepath.Join(m.workDir, routeKey)
	if cfg.WorkDir != "" {
		targetWorkDir = cfg.WorkDir.Path()
	}

	c, err := New(Config{
		ID:       routeKey,
		URL:      cfg.URL,
		Branch:   cfg.Branch,
		WorkDir:  targetWorkDir,
		Logger:   m.logger,
		KeepLast: 2,
		Auth: AuthConfig{
			Type:             cfg.Auth.Type,
			Username:         cfg.Auth.Username,
			Password:         cfg.Auth.Password.String(),
			SSHKey:           cfg.Auth.SSHKey.String(),
			SSHKeyPassphrase: cfg.Auth.SSHKeyPassphrase.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create cook for %s: %w", routeKey, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.entries.Set(routeKey, &Entry{Cook: c, Config: cfg, ctx: ctx, cancel: cancel})
	m.logger.Fields(
		"route_key", routeKey,
		"mode", cfg.Mode,
		"webhook", "/.well-known/agbero/webhook/git/"+routeKey,
	).Info("git integration configured")

	// Always submit an initial clone/pull.
	if err := m.pool.Submit(jack.Func(func() error {
		if err := c.Make(ctx); err != nil {
			if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
				m.logger.Fields("route", routeKey, "err", err).Error("initial git pull failed")
			}
		}
		return nil
	})); err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue initial deployment")
	}

	// Start interval poller only for pull/both modes.
	if cfg.IsPull() && cfg.Interval > 0 {
		m.wg.Add(1)
		go m.poll(ctx, routeKey, c, cfg.Interval.StdDuration())
	}

	return nil
}

// registerPushOnly handles git blocks with no URL — content arrives via webhook only.
// The work directory is created immediately so the web handler serves content
// without waiting for a clone that will never happen.
func (m *Manager) registerPushOnly(routeKey string, cfg alaye.Git) error {
	if cfg.Secret.String() == "" {
		return errors.New("git: push-only mode (no url) requires a secret")
	}

	if existing, ok := m.entries.Get(routeKey); ok {
		if existing.Config.Secret == cfg.Secret {
			m.logger.Fields("route_key", routeKey).Debug("push-only git already registered, skipping")
			return nil
		}
		if existing.cancel != nil {
			existing.cancel()
		}
	}

	targetWorkDir := filepath.Join(m.workDir, routeKey)
	if cfg.WorkDir != "" {
		targetWorkDir = cfg.WorkDir.Path()
	}

	if err := os.MkdirAll(targetWorkDir, defaultWorkDirPerm); err != nil {
		return fmt.Errorf("push-only: create work dir: %w", err)
	}

	c, err := New(Config{
		ID:      routeKey,
		URL:     "", // no clone
		WorkDir: targetWorkDir,
		Logger:  m.logger,
	})
	if err != nil {
		return fmt.Errorf("push-only cook for %s: %w", routeKey, err)
	}

	// Mark the work directory as ready so CurrentPath returns immediately.
	c.SetCurrentPath(targetWorkDir)

	ctx, cancel := context.WithCancel(context.Background())
	m.entries.Set(routeKey, &Entry{Cook: c, Config: cfg, ctx: ctx, cancel: cancel})
	m.logger.Fields(
		"route_key", routeKey,
		"mode", "push-only",
		"work_dir", targetWorkDir,
		"webhook", "/.well-known/agbero/webhook/git/"+routeKey,
	).Info("push-only git integration configured")

	return nil
}

// Prune stops and removes any git integration whose key is not in activeIDs.
func (m *Manager) Prune(activeIDs map[string]bool) {
	var toDelete []string
	m.entries.Range(func(key string, _ *Entry) bool {
		if !activeIDs[key] {
			toDelete = append(toDelete, key)
		}
		return true
	})
	for _, key := range toDelete {
		m.logger.Fields("route_key", key).Info("git integration removed from config, stopping")
		m.Unregister(key)
	}
}

// Unregister stops and removes a single git integration.
func (m *Manager) Unregister(routeKey string) {
	if entry, ok := m.entries.Get(routeKey); ok {
		m.entries.Delete(routeKey)
		if entry.cancel != nil {
			entry.cancel()
		}
	}
}

// CurrentPath returns the filesystem path currently being served for routeKey.
func (m *Manager) CurrentPath(routeKey string) string {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		return ""
	}
	basePath := entry.Cook.CurrentPath()
	if basePath == "" {
		return ""
	}
	if entry.Config.SubDir != "" {
		return filepath.Join(basePath, entry.Config.SubDir)
	}
	return basePath
}

// GetCook returns the Cook for a given route key.
func (m *Manager) GetCook(routeKey string) (*Cook, bool) {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		return nil, false
	}
	return entry.Cook, true
}

// Stop cancels all integrations and waits for pollers to exit.
func (m *Manager) Stop() {
	m.entries.Range(func(_ string, entry *Entry) bool {
		if entry.cancel != nil {
			entry.cancel()
		}
		return true
	})

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(defaultStopTimeout):
		m.logger.Warn("timeout waiting for pollers")
	}
}

// HandleWebhook processes an inbound webhook for the given route key.
//
// Pull-only entries return 405. Push and push-only entries validate the
// HMAC signature, then either trigger Make (pull/both) or write the
// payload directly to the work directory (push-only).
func (m *Manager) HandleWebhook(w http.ResponseWriter, r *http.Request, routeKey string) {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Pull-only: webhook endpoint exists but is not active.
	if entry.Config.Mode == alaye.GitModePull {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to read webhook body")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Validate HMAC signature when a secret is configured.
	if entry.Config.Secret.String() != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if sig == "" {
			sig = r.Header.Get("X-Hub-Signature")
		}
		mac := hmac.New(sha256.New, []byte(entry.Config.Secret.String()))
		mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
			m.logger.Fields("route", routeKey).Warn("invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}
	}

	// Push-only mode: write payload to work directory, no git pull.
	if entry.Config.URL == "" {
		if err := m.writePushPayload(entry, body); err != nil {
			m.logger.Fields("route", routeKey, "err", err).Error("push-only write failed")
			http.Error(w, "Write Failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("Content Received"))
		return
	}

	// Pull/both mode: check branch filter then trigger Make.
	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err == nil {
		if entry.Config.Branch != "" && payload.Ref != "" {
			expected := "refs/heads/" + entry.Config.Branch
			if payload.Ref != expected {
				m.logger.Fields("route", routeKey, "ref", payload.Ref, "expected", expected).
					Info("ignoring webhook for different branch")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Ignored: branch mismatch"))
				return
			}
		}
	}

	if err := m.pool.Submit(jack.Func(func() error {
		if _, exists := m.entries.Get(routeKey); !exists {
			m.logger.Fields("route", routeKey).Info("ghost deployment prevented: route unregistered")
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultWebhookTimeout)
		defer cancel()
		if err := entry.Cook.Make(ctx); err != nil {
			if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
				m.logger.Fields("route", routeKey, "err", err).Error("webhook deployment failed")
			}
		}
		return nil
	})); err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue webhook deployment")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("Deployment Triggered"))
}

// writePushPayload writes the raw webhook body to payload.json in the
// push-only work directory. The web handler then serves from that directory.
func (m *Manager) writePushPayload(entry *Entry, body []byte) error {
	workDir := entry.Cook.CurrentPath()
	if workDir == "" {
		return errors.New("push-only work directory not available")
	}
	return os.WriteFile(filepath.Join(workDir, "payload.json"), body, 0644)
}

// WebhookHandler returns an http.HandlerFunc for a specific route key.
func (m *Manager) WebhookHandler(routeKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		m.HandleWebhook(w, r, routeKey)
	}
}

// Health returns a status summary of all registered integrations.
func (m *Manager) Health() map[string]HealthStatus {
	status := make(map[string]HealthStatus)
	m.entries.Range(func(key string, entry *Entry) bool {
		path := entry.Cook.CurrentPath()
		state := "healthy"
		if path == "" {
			state = "unavailable"
		}
		deps, _ := entry.Cook.ListDeployments()
		status[key] = HealthStatus{
			State:       state,
			CurrentPath: path,
			Commit:      entry.Cook.CurrentCommit(),
			Deployments: len(deps),
		}
		return true
	})
	return status
}

// poll submits periodic Make calls for pull/both mode integrations.
func (m *Manager) poll(ctx context.Context, routeKey string, c *Cook, interval time.Duration) {
	defer m.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.pool.Submit(jack.Func(func() error {
				if _, exists := m.entries.Get(routeKey); !exists {
					return nil
				}
				if err := c.Make(ctx); err != nil {
					if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
						m.logger.Fields("route", routeKey, "err", err).Error("scheduled git pull failed")
					}
				}
				return nil
			})); err != nil {
				m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue scheduled deployment")
			}
		case <-ctx.Done():
			return
		}
	}
}

// HealthStatus summarises the state of a single git integration.
type HealthStatus struct {
	State       string `json:"state"`
	CurrentPath string `json:"current_path"`
	Commit      string `json:"commit"`
	Deployments int    `json:"deployments"`
}
