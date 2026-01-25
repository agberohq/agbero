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

// HostManager abstracts the host/router update logic.
// - UpdateGossipNode MUST MERGE backends into an existing host+path route.
// - RemoveGossipNode MUST REMOVE all backends registered by nodeID and delete empty routes.
type HostManager interface {
	UpdateGossipNode(nodeID, host string, route alaye.Route)
	RemoveGossipNode(nodeID string)
	ResetNodeFailures(nodeName string)
}

// logAdapter maps memberlist's stdlib log output into ll.Logger
// and filters noisy spam.
type logAdapter struct {
	logger *ll.Logger
}

func (l *logAdapter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))

	// Drop noisy periodic spam
	if strings.Contains(msg, "Stream connection") ||
		strings.Contains(msg, "Initiating push/pull sync") {
		return len(p), nil
	}

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
//
// Token is OPTIONAL now (meta size limits).
// If token is missing and auth is enabled, Agbero fetches via AuthPath.
//
// NOTE: Add fields as needed, but keep meta SMALL.
type AppMeta struct {
	Token string `json:"token,omitempty"`
	Port  int    `json:"port"`

	Host        string `json:"host"`            // e.g. "myapp.localhost"
	Path        string `json:"path"`            // e.g. "/api"
	StripPrefix bool   `json:"strip,omitempty"` // if true: strip Path before forwarding

	AuthPath string `json:"auth_path,omitempty"` // default "/.well-known/agbero"

	// Optional hints
	Weight     int    `json:"weight,omitempty"`      // backend weight (default 1)
	HealthPath string `json:"health_path,omitempty"` // default "/"
}

type Service struct {
	list         *memberlist.Memberlist
	hm           HostManager
	logger       *ll.Logger
	tokenManager *security.TokenManager

	localName string

	// liveness tracking: node -> lastSeen time
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
		defaultTTL:   30 * time.Second,
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

	// Keep naming behavior
	c.Name = "agbero-" + c.Name

	c.BindPort = cfg.Port
	if c.BindPort == 0 {
		c.BindPort = 7946
	}

	if cfg.SecretKey != "" {
		key := []byte(cfg.SecretKey)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("gossip secret key must be 16, 24, or 32 bytes")
		}
		c.SecretKey = key
	}

	// Reduce anti-entropy spam
	c.PushPullInterval = 60 * time.Second

	// capture local name early
	s.localName = c.Name

	// events hook
	c.Events = &eventDelegate{s: s}

	// memberlist logs filtered
	c.Logger = log.New(&logAdapter{logger: logger}, "[gossip] ", 0)

	list, err := memberlist.Create(c)
	if err != nil {
		return nil, err
	}
	s.list = list

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
// NOTE: RemoveGossipNode must remove ALL backends for that node and delete empty routes.
func (s *Service) StartGC(ttl time.Duration) {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	s.ttl = ttl

	go func() {
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
						s.logger.Fields("node", name, "ttl", ttl.String()).
							Warn("gossip GC removed stale node")
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
	e.s.lastSeen.Store(node.Name, time.Now())
	e.processNode(node)
	e.s.logger.Fields("node", node.Name).Info("node joined")
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
	e.s.lastSeen.Store(node.Name, time.Now())
	e.s.hm.ResetNodeFailures(node.Name)
	e.s.logger.Fields("node", node.Name).Debug("node alive ping received")
}

// fetchToken pulls token from the service if it was not provided in gossip meta.
func (e *eventDelegate) fetchToken(node *memberlist.Node, meta *AppMeta) (string, error) {
	authPath := meta.AuthPath
	if authPath == "" {
		authPath = "/.well-known/agbero"
	}

	// IMPORTANT: uses meta.Port (service port) — keep auth endpoint on service port
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
		// Without meta, it can't be routed.
		return
	}

	var meta AppMeta
	if err := json.Unmarshal(node.Meta, &meta); err != nil {
		e.s.logger.Fields("node", node.Name, "err", err).Warn("gossip invalid metadata")
		return
	}

	// Basic validation
	if meta.Host == "" || meta.Port <= 0 {
		return
	}

	if meta.Path == "" {
		meta.Path = "/"
	}
	if !strings.HasPrefix(meta.Path, "/") {
		meta.Path = "/" + meta.Path
	}

	// Security (optional)
	if e.s.tokenManager != nil {
		if meta.Token == "" {
			tok, err := e.fetchToken(node, &meta)
			if err != nil {
				e.s.logger.Fields("node", node.Name, "err", err).
					Warn("gossip rejected: auth fetch failed")
				return
			}
			meta.Token = tok
		}

		svcName, err := e.s.tokenManager.Verify(meta.Token)
		if err != nil {
			e.s.logger.Fields("node", node.Name, "err", err).
				Warn("gossip rejected: invalid token")
			return
		}
		e.s.logger.Fields("node", node.Name, "svc", svcName).Debug("gossip authorized")
	}

	weight := meta.Weight
	if weight <= 0 {
		weight = 1
	}

	healthPath := meta.HealthPath
	if healthPath == "" {
		healthPath = "/"
	}
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = "/" + healthPath
	}

	// Agbero forwards to the node IP memberlist sees + meta.Port
	target := fmt.Sprintf("http://%s:%d", node.Addr.String(), meta.Port)

	// Build route:
	// IMPORTANT: The same host+path can be registered by multiple nodes.
	// HostManager MUST MERGE backends for same host+path (not reject duplicates).
	route := alaye.Route{
		Path: meta.Path,

		Backends: alaye.Backend{
			// strategy for *this dynamic route*:
			// random is usually fine; round_robin also ok.
			LBStrategy: alaye.StrategyRoundRobin,
			Servers: []alaye.Server{
				{
					Address: target,
					Weight:  weight,
				},
			},
		},

		HealthCheck: &alaye.HealthCheck{
			Path: healthPath,
		},
	}

	if meta.StripPrefix {
		route.StripPrefixes = []string{meta.Path}
	}

	e.s.hm.UpdateGossipNode(node.Name, meta.Host, route)

	e.s.logger.Fields(
		"node", node.Name,
		"host", meta.Host,
		"path", meta.Path,
		"target", target,
		"weight", weight,
	).Info("gossip route upserted")
}
