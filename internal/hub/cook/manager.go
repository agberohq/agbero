package cook

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
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
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

type WebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

type ManagerConfig struct {
	WorkDir expect.Folder
	Pool    *jack.Pool
	Logger  *ll.Logger
}

type Manager struct {
	entries *mappo.Concurrent[string, *Entry]
	logger  *ll.Logger
	workDir string
	pool    *jack.Pool
	wg      sync.WaitGroup
}

type Entry struct {
	Cook   *Cook
	Config alaye.Git
	ctx    context.Context
	cancel context.CancelFunc
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.WorkDir == "" {
		return nil, errors.New("work directory is required")
	}
	if cfg.Pool == nil {
		return nil, errors.New("worker pool is required")
	}
	if err := cfg.WorkDir.Init(def.WorkDirPerm); err != nil {
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

	if cfg.IsPull() && cfg.Interval > 0 {
		m.wg.Add(1)
		go m.poll(ctx, routeKey, c, cfg.Interval.StdDuration())
	}

	return nil
}

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

	if err := os.MkdirAll(targetWorkDir, def.WorkDirPerm); err != nil {
		return fmt.Errorf("push-only: create work dir: %w", err)
	}

	c, err := New(Config{
		ID:      routeKey,
		URL:     "",
		WorkDir: targetWorkDir,
		Logger:  m.logger,
	})
	if err != nil {
		return fmt.Errorf("push-only cook for %s: %w", routeKey, err)
	}

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

func (m *Manager) Unregister(routeKey string) {
	if entry, ok := m.entries.Get(routeKey); ok {
		m.entries.Delete(routeKey)
		if entry.cancel != nil {
			entry.cancel()
		}
	}
}

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

func (m *Manager) GetCook(routeKey string) (*Cook, bool) {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		return nil, false
	}
	return entry.Cook, true
}

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
	case <-time.After(def.CookTimeoutStop):
		m.logger.Warn("timeout waiting for pollers")
	}
}

func (m *Manager) HandleWebhook(w http.ResponseWriter, r *http.Request, routeKey string) {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if entry.Config.Mode == def.GitModePull {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, def.CookWebhookBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to read webhook body")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if entry.Config.Secret.String() != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		var expected string
		if sig != "" {
			// SHA-256 path — the preferred modern signature.
			mac := hmac.New(sha256.New, []byte(entry.Config.Secret.String()))
			mac.Write(body)
			expected = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		} else {
			// SHA-1 fallback — used by older GitHub Enterprise and other
			// Git providers that only send X-Hub-Signature.
			// Must compute SHA-1 HMAC and compare against "sha1=..." prefix,
			// not SHA-256. Computing SHA-256 here always produces a mismatch.
			sig = r.Header.Get("X-Hub-Signature")
			mac := hmac.New(sha1.New, []byte(entry.Config.Secret.String()))
			mac.Write(body)
			expected = "sha1=" + hex.EncodeToString(mac.Sum(nil))
		}
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
			m.logger.Fields("route", routeKey).Warn("invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}
	}

	var payload WebhookPayload
	_ = json.Unmarshal(body, &payload)

	// A push-only route (Config.URL == "") is deliberately configured that way
	// by the operator. Allowing a webhook payload to supply a clone URL and
	// silently upgrade the route to a full git-clone deploy is an unauthenticated
	// RCE vector: an attacker who can send a forged webhook (or who controls the
	// upstream repository metadata) can point the route at an arbitrary repo and
	// have the Orchestrator execute its contents. The upgrade block has been
	// removed. Push-only routes stay push-only; clone URLs must be set in config.

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

	if err := m.pool.Submit(jack.Func(func() error {
		if _, exists := m.entries.Get(routeKey); !exists {
			m.logger.Fields("route", routeKey).Info("ghost deployment prevented: route unregistered")
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), def.CookTimeoutStop)
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

func (m *Manager) writePushPayload(entry *Entry, body []byte) error {
	workDir := entry.Cook.CurrentPath()
	if workDir == "" {
		return errors.New("push-only work directory not available")
	}
	return os.WriteFile(filepath.Join(workDir, ".payload.json"), body, def.ConfigFilePerm)
}

func (m *Manager) WebhookHandler(routeKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		m.HandleWebhook(w, r, routeKey)
	}
}

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

type HealthStatus struct {
	State       string `json:"state"`
	CurrentPath string `json:"current_path"`
	Commit      string `json:"commit"`
	Deployments int    `json:"deployments"`
}
