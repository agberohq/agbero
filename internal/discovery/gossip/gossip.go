package gossip

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

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

type logAdapter struct {
	logger *ll.Logger
}

func (l *logAdapter) Write(p []byte) (n int, err error) {
	l.logger.Info(strings.TrimSpace(string(p)))
	return len(p), nil
}

// AppMeta defines the routing contract sent by the application
type AppMeta struct {
	Token string `json:"token"`
	Port  int    `json:"port"`

	// Routing Logic
	Host        string `json:"host"`            // e.g. "myapp.com"
	Path        string `json:"path"`            // e.g. "/danceapp"
	StripPrefix bool   `json:"strip,omitempty"` // If true, strip 'path' before forwarding
}

type Service struct {
	list         *memberlist.Memberlist
	hm           HostManager // Interface type
	logger       *ll.Logger
	tokenManager *security.TokenManager
	localName    string // Stored to avoid nil pointer during startup events
}

func NewService(hm HostManager, cfg *alaye.Gossip, logger *ll.Logger) (*Service, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	s := &Service{
		hm:     hm,
		logger: logger,
	}

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

	// Capture local name before starting, so events can check "self" without s.list being ready
	s.localName = c.Name
	c.Events = &eventDelegate{s: s}
	c.Logger = log.New(&logAdapter{logger: logger}, "[gossip] ", 0)

	list, err := memberlist.Create(c)
	if err != nil {
		return nil, err
	}
	s.list = list

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
	if s.list != nil {
		return s.list.Shutdown()
	}
	return nil
}

type eventDelegate struct {
	s *Service
}

func (e *eventDelegate) NotifyJoin(node *memberlist.Node) {
	// Use stored localName to avoid nil pointer on e.s.list during startup
	if node.Name == e.s.localName {
		return
	}
	e.processNode(node)
	// Mark healthy on join
	e.s.logger.Fields("node", node.Name).Info("node joined and marked healthy")
}

func (e *eventDelegate) NotifyLeave(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	e.s.hm.RemoveGossipNode(node.Name)
}

func (e *eventDelegate) NotifyUpdate(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	e.processNode(node)
}

func (e *eventDelegate) NotifyAlive(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	// Reset failures on alive ping
	e.s.hm.ResetNodeFailures(node.Name)
	e.s.logger.Fields("node", node.Name).Debug("node alive ping received")
}

func (e *eventDelegate) processNode(node *memberlist.Node) {
	var meta AppMeta
	if len(node.Meta) == 0 {
		return
	}

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
		if meta.Token == "" {
			e.s.logger.Fields("node", node.Name).Warn("gossip rejected: missing token")
			return
		}

		svcName, err := e.s.tokenManager.Verify(meta.Token)
		if err != nil {
			e.s.logger.Fields("node", node.Name, "err", err).Warn("gossip rejected: invalid token")
			return
		}
		e.s.logger.Fields("node", node.Name, "svc", svcName).Debug("gossip authorized")
	}

	target := fmt.Sprintf("http://%s:%d", node.Addr.String(), meta.Port)

	// Construct route definition
	route := alaye.Route{
		Path: meta.Path,
		Backends: alaye.Backend{
			LBStrategy: alaye.StrategyRandom,
			Servers: []alaye.Server{
				{
					Address: target,
					Weight:  1, // Default weight for gossip nodes
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

	// Dedup: Check if same path/host already registered by another node
	if e.s.hm.RouteExists(meta.Host, route.Path) {
		e.s.logger.Fields("node", node.Name, "host", meta.Host, "path", route.Path).Warn("duplicate route; skipping")
		return
	}

	// Inject into hostManager
	e.s.hm.UpdateGossipNode(node.Name, meta.Host, route)
}
