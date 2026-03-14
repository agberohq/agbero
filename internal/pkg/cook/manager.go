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
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type WebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

type Manager struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	logger  *ll.Logger
	workDir string
	pool    *jack.Pool
	wg      sync.WaitGroup
}

type Entry struct {
	Cook   *Cook
	Config alaye.Git
	cancel context.CancelFunc
}

func NewManager(workDir string, pool *jack.Pool, logger *ll.Logger) (*Manager, error) {
	if workDir == "" {
		return nil, errors.New("work directory is required")
	}
	if pool == nil {
		return nil, errors.New("worker pool is required")
	}

	if err := os.MkdirAll(workDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create manager workdir: %w", err)
	}

	return &Manager{
		entries: make(map[string]*Entry),
		logger:  logger.Namespace("cookmgr"),
		workDir: workDir,
		pool:    pool,
	}, nil
}

func (m *Manager) Register(routeKey string, cfg alaye.Git) error {
	if cfg.URL == "" {
		return errors.New("git URL is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.entries[routeKey]; ok {
		if existing.cancel != nil {
			existing.cancel()
		}
		delete(m.entries, routeKey)
	}

	cookCfg := Config{
		ID:       routeKey,
		URL:      cfg.URL,
		Branch:   cfg.Branch,
		WorkDir:  m.workDir,
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
		cancel: cancel,
	}
	m.entries[routeKey] = entry

	m.logger.Fields("route_key", routeKey, "webhook", "/.well-known/agbero/webhook/git/"+routeKey).Info("git integration configured")

	err = m.pool.Submit(jack.Func(func() error {
		if err := c.Make(ctx); err != nil {
			m.logger.Fields("route", routeKey, "err", err).Error("initial git pull failed")
		}
		return nil
	}))

	if err != nil {
		m.logger.Fields("route", routeKey, "err", err).Warn("failed to queue initial deployment")
	}

	if cfg.Interval > 0 {
		m.wg.Add(1)
		go m.poll(ctx, routeKey, c, cfg.Interval)
	}

	return nil
}

func (m *Manager) Unregister(routeKey string) {
	m.mu.Lock()
	entry, ok := m.entries[routeKey]
	delete(m.entries, routeKey)
	m.mu.Unlock()

	if ok && entry.cancel != nil {
		entry.cancel()
	}
}

func (m *Manager) CurrentPath(routeKey string) string {
	m.mu.RLock()
	entry, ok := m.entries[routeKey]
	m.mu.RUnlock()

	if !ok {
		return ""
	}
	return entry.Cook.CurrentPath()
}

func (m *Manager) GetCook(routeKey string) (*Cook, bool) {
	m.mu.RLock()
	entry, ok := m.entries[routeKey]
	m.mu.RUnlock()

	if !ok {
		return nil, false
	}
	return entry.Cook, true
}

func (m *Manager) Stop() {
	m.mu.Lock()
	for _, entry := range m.entries {
		if entry.cancel != nil {
			entry.cancel()
		}
	}
	m.entries = make(map[string]*Entry)
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
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
				if err := c.Make(ctx); err != nil {
					m.logger.Fields("route", routeKey, "err", err).Error("scheduled git pull failed")
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
	m.mu.RLock()
	entry, ok := m.entries[routeKey]
	m.mu.RUnlock()

	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := entry.Cook.Make(ctx); err != nil {
			m.logger.Fields("route", routeKey, "err", err).Error("webhook deployment failed")
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
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]HealthStatus)
	for key, entry := range m.entries {
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
	}

	return status
}

type HealthStatus struct {
	State       string `json:"state"`
	CurrentPath string `json:"current_path"`
	Commit      string `json:"commit"`
	Deployments int    `json:"deployments"`
}
