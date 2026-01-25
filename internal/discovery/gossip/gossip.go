package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

// HostManager interface abstracts the Host discovery logic for testing
type HostManager interface {
	UpdateGossipNode(nodeID, host string, route alaye.Route)
	RemoveGossipNode(nodeID string)
	RouteExists(host, path string) bool
	ResetNodeFailures(nodeName string)
}

// logAdapter maps memberlist's stdlib log output into ll.Logger.
// It also filters the most chatty memberlist debug lines so it doesn't litter your logs.
type logAdapter struct {
	logger *ll.Logger
}

func (l *logAdapter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))

	// Drop the noisiest periodic logs completely
	if strings.Contains(msg, "Stream connection") ||
		strings.Contains(msg, "Initiating push/pull sync") {
		return len(p), nil
	}

	// Map memberlist log tags to your logger levels
	switch {
	case strings.Contains(msg, "[DEBUG]"):
		l.logger.Debug(msg)
	case strings.Contains(msg, "[WARN]"):
		l.logger.Warn(msg)
	case strings.Contains(msg, "[ERR]"):
		l.logger.Error(msg)
	default:
		l.logger.Info(msg)
	}

	return len(p), nil
}

// AppMeta defines the routing contract sent by the application.
// NOTE: token is OPTIONAL in gossip meta now (to avoid memberlist meta size limits).
// If token is missing and auth is enabled, Agbero will fetch it via AuthPath.
type AppMeta struct {
	Token string `json:"token,omitempty"`
	Port  int    `json:"port"`

	// Routing Logic
	Host        string `json:"host"`            // e.g. "myapp.com"
	Path        string `json:"path"`            // e.g. "/danceapp"
	StripPrefix bool   `json:"strip,omitempty"` // If true, strip 'path' before forwarding

	// Optional: service-side auth endpoint for Agbero to fetch a large token.
	// Default: "/.well-known/agbero"
	AuthPath string `json:"auth_path,omitempty"`
}

type Service struct {
	list         *memberlist.Memberlist
	hm           HostManager
	logger       *ll.Logger
	tokenManager *security.TokenManager

	localName string

	// --- liveness tracking to aggressively unregister stale nodes ---
	lastSeen sync.Map // map[string]time.Time

	// GC config
	ttl          time.Duration
	gcStop       chan struct{}
	gcStopOnce   sync.Once
	authTimeout  time.Duration
	defaultTTL   time.Duration
	defaultAuthT time.Duration
}

func NewService(hm HostManager, cfg *alaye.Gossip, logger *ll.Logger) (*Service, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	s := &Service{
		hm:           hm,
		logger:       logger,
		gcStop:       make(chan struct{}),
		defaultTTL:   30 * time.Second, // good default for LB discovery
		defaultAuthT: 2 * time.Second,
		authTimeout:  2 * time.Second,
	}

	// Gossip auth (Agbero holds private key; services present minted tokens)
	if cfg.PrivateKeyFile != "" {
		tm, err := security.LoadKeys(cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("gossip auth enabled but key failed: %w", err)
		}
		s.tokenManager = tm
		logger.Info("gossip authorization enabled (Ed25519)")
	} else {
		logger.Warn("gossip running WITHOUT application authorization (insecure)")
	}

	c := memberlist.DefaultLANConfig()

	// Keep your existing naming behavior
	c.Name = "agbero-" + c.Name

	c.BindPort = cfg.Port
	if c.BindPort == 0 {
		c.BindPort = 7946
	}

	// If you ever turn on encryption at transport layer, this will be used.
	// But user said they don't need SecretKey.
	if cfg.SecretKey != "" {
		key := []byte(cfg.SecretKey)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("gossip secret key must be 16, 24, or 32 bytes")
		}
		c.SecretKey = key
	}

	// Reduce anti-entropy spam + network noise (optional but recommended for LB discovery)
	// You can tune this higher (e.g., 60s or 120s) if you want even less chatter.
	c.PushPullInterval = 60 * time.Second

	// Capture local name before starting, so events can check "self" without s.list being ready
	s.localName = c.Name

	// Events hook
	c.Events = &eventDelegate{s: s}

	// Wire memberlist logs (filtered)
	c.Logger = log.New(&logAdapter{logger: logger}, "[gossip] ", 0)

	list, err := memberlist.Create(c)
	if err != nil {
		return nil, err
	}
	s.list = list

	// Start aggressive GC for stale nodes (important for unregistering when nodes die ungracefully)
	ttl := s.defaultTTL
	if cfg.TTL > 0 {
		ttl = time.Duration(cfg.TTL) * time.Second
	}
	s.StartGC(ttl)

	return s, nil
}

func (s *Service) Join(seeds []string) error {
	if len(seeds) > 0 {
		_, err := s.list.Join(seeds)
		return err
	}
	return nil
}

func (s *Service) Shutdown() error {
	s.stopGC()
	if s.list != nil {
		return s.list.Shutdown()
	}
	return nil
}

// StartGC unregisters nodes that haven't sent NotifyAlive within ttl.
// This solves the "server disconnected but not unregistered" problem.
func (s *Service) StartGC(ttl time.Duration) {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	s.ttl = ttl

	go func() {
		// Run often enough to evict quickly without being noisy
		ticker := time.NewTicker(ttl / 2)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				s.lastSeen.Range(func(k, v any) bool {
					name, _ := k.(string)
					seen, _ := v.(time.Time)

					if name == "" {
						return true
					}

					if now.Sub(seen) > ttl {
						s.hm.RemoveGossipNode(name)
						s.lastSeen.Delete(name)
						s.logger.Fields("node", name, "ttl", ttl.String()).Warn("gossip GC removed stale node")
					}
					return true
				})

			case <-s.gcStop:
				return
			}
		}
	}()
}

func (s *Service) stopGC() {
	s.gcStopOnce.Do(func() {
		close(s.gcStop)
	})
}

type eventDelegate struct {
	s *Service
}

func (e *eventDelegate) NotifyJoin(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}

	// mark seen immediately
	e.s.lastSeen.Store(node.Name, time.Now())

	e.processNode(node)
	e.s.logger.Fields("node", node.Name).Info("node joined and marked healthy")
}

func (e *eventDelegate) NotifyLeave(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}

	e.s.hm.RemoveGossipNode(node.Name)
	e.s.lastSeen.Delete(node.Name)
	e.s.logger.Fields("node", node.Name).Info("node left and unregistered")
}

func (e *eventDelegate) NotifyUpdate(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}

	e.s.lastSeen.Store(node.Name, time.Now())
	e.processNode(node)
}

func (e *eventDelegate) NotifyAlive(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}

	// This is the key to fast cleanup: track last seen.
	e.s.lastSeen.Store(node.Name, time.Now())

	// Reset failures on alive ping
	e.s.hm.ResetNodeFailures(node.Name)
	e.s.logger.Fields("node", node.Name).Debug("node alive ping received")
}

// fetchToken pulls a large token from the service if it was not provided in gossip meta.
// This avoids memberlist meta size limits while keeping Agbero as the authority.
func (e *eventDelegate) fetchToken(node *memberlist.Node, meta *AppMeta) (string, error) {
	authPath := meta.AuthPath
	if authPath == "" {
		authPath = "/.well-known/agbero"
	}

	url := fmt.Sprintf("http://%s:%d%s", node.Addr.String(), meta.Port, authPath)

	ctx, cancel := context.WithTimeout(context.Background(), e.s.authTimeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth endpoint status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token from auth endpoint")
	}
	return out.Token, nil
}

func (e *eventDelegate) processNode(node *memberlist.Node) {
	if len(node.Meta) == 0 {
		// If a node isn't publishing meta, it can't be routed.
		return
	}

	var meta AppMeta
	if err := json.Unmarshal(node.Meta, &meta); err != nil {
		e.s.logger.Fields("node", node.Name).Warn("gossip invalid metadata")
		return
	}

	// Basic Validation
	if meta.Host == "" || meta.Port == 0 {
		return
	}

	// Security Check
	if e.s.tokenManager != nil {
		// Token can be omitted from gossip meta; fetch it from the service.
		if meta.Token == "" {
			tok, err := e.fetchToken(node, &meta)
			if err != nil {
				e.s.logger.Fields("node", node.Name, "err", err).Warn("gossip rejected: auth fetch failed")
				return
			}
			meta.Token = tok
		}

		svcName, err := e.s.tokenManager.Verify(meta.Token)
		if err != nil {
			e.s.logger.Fields("node", node.Name, "err", err).Warn("gossip rejected: invalid token")
			return
		}
		e.s.logger.Fields("node", node.Name, "svc", svcName).Debug("gossip authorized")
	}

	// Agbero forwards to the node IP memberlist sees + meta.Port
	target := fmt.Sprintf("http://%s:%d", node.Addr.String(), meta.Port)

	route := alaye.Route{
		Path: meta.Path,
		Backends: alaye.Backend{
			LBStrategy: alaye.StrategyRandom,
			Servers: []alaye.Server{
				{
					Address: target,
					Weight:  1,
				},
			},
		},
		HealthCheck: &alaye.HealthCheck{
			Path: "/",
		},
	}

	if route.Path == "" {
		route.Path = "/"
	}

	if meta.StripPrefix {
		route.StripPrefixes = []string{route.Path}
	}

	// Dedup: same host+path already registered by another node
	if e.s.hm.RouteExists(meta.Host, route.Path) {
		e.s.logger.Fields("node", node.Name, "host", meta.Host, "path", route.Path).Warn("duplicate route; skipping")
		return
	}

	e.s.hm.UpdateGossipNode(node.Name, meta.Host, route)
}
