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

// Registers a new Git repository configuration for background polling and webhooks
// Merges intervals and secrets if an identical repository clone is already active
func (m *Manager) Register(routeKey string, cfg alaye.Git) error {

	if cfg.URL == "" {
		return errors.New("git URL is required")
	}

	if existing, ok := m.entries.Get(routeKey); ok {
		if existing.Config.URL == cfg.URL &&
			existing.Config.Branch == cfg.Branch &&
			existing.Config.WorkDir == cfg.WorkDir &&
			existing.Config.Interval == cfg.Interval &&
			existing.Config.Secret == cfg.Secret &&
			existing.Config.Auth.Type == cfg.Auth.Type &&
			existing.Config.Auth.Username == cfg.Auth.Username {

			m.logger.Fields("route_key", routeKey).Debug("git integration already configured for this repository, skipping clone")
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

	cookCfg := Config{
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
	}

	c, err := New(cookCfg)
	if err != nil {
		return fmt.Errorf("failed to create cook for %s: %w", routeKey, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	entry := &Entry{
		Cook:   c,
		Config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	m.entries.Set(routeKey, entry)

	m.logger.Fields("route_key", routeKey, "webhook", "/.well-known/agbero/webhook/git/"+routeKey).Info("git integration configured")

	err = m.pool.Submit(jack.Func(func() error {
		if err := c.Make(ctx); err != nil {
			// Suppress context canceled errors so it doesn't look like a bug during overwrites
			if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
				m.logger.Fields("route", routeKey, "err", err).Error("initial git pull failed")
			}
		}
		return nil
	}))

	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue initial deployment")
	}

	if cfg.Interval > 0 {
		m.wg.Add(1)
		go m.poll(ctx, routeKey, c, cfg.Interval.StdDuration())
	}

	return nil
}

func (m *Manager) Prune(activeIDs map[string]bool) {
	var toDelete []string
	m.entries.Range(func(key string, entry *Entry) bool {
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
	m.entries.Range(func(key string, entry *Entry) bool {
		if entry.cancel != nil {
			entry.cancel()
		}
		return true
	})
	m.entries.Clear()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(defaultStopTimeout):
		m.logger.Warn("timeout waiting for cook operations to complete")
	}
}

func (m *Manager) poll(ctx context.Context, routeKey string, c *Cook, interval time.Duration) {
	defer m.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := m.pool.Submit(jack.Func(func() error {
				if _, exists := m.entries.Get(routeKey); !exists {
					return nil
				}

				if err := c.Make(ctx); err != nil {
					if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
						m.logger.Fields("route", routeKey, "err", err).Error("scheduled git pull failed")
					}
				}
				return nil
			}))
			if err != nil {
				m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue scheduled deployment")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) HandleWebhook(w http.ResponseWriter, r *http.Request, routeKey string) {
	entry, ok := m.entries.Get(routeKey)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to read webhook body")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if entry.Config.Secret != "" {
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			signature = r.Header.Get("X-Hub-Signature")
		}
		mac := hmac.New(sha256.New, []byte(entry.Config.Secret.String()))
		mac.Write(body)
		expectedMAC := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedMAC)) != 1 {
			m.logger.Fields("route", routeKey).Warn("invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err == nil {
		if entry.Config.Branch != "" && payload.Ref != "" {
			expectedRef := "refs/heads/" + entry.Config.Branch
			if payload.Ref != expectedRef {
				m.logger.Fields("route", routeKey, "ref", payload.Ref, "expected", expectedRef).Info("ignoring webhook for different branch")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Ignored: branch mismatch"))
				return
			}
		}
	}

	err = m.pool.Submit(jack.Func(func() error {
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
	}))

	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue webhook deployment")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("Deployment Triggered"))
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

type HealthStatus struct {
	State       string `json:"state"`
	CurrentPath string `json:"current_path"`
	Commit      string `json:"commit"`
	Deployments int    `json:"deployments"`
}
