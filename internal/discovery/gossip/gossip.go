package gossip

import (
	"fmt"
	"log"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

// Hosting abstracts the host/router update logic.
type Hosting interface {
	UpdateGossipNode(nodeID, host string, route alaye.Route)
	RemoveGossipNode(nodeID string)
	ResetNodeFailures(nodeName string)
}

type Service struct {
	list         *memberlist.Memberlist
	hm           Hosting
	logger       *ll.Logger
	tokenManager *security.TokenManager

	localName string

	authTimeout time.Duration
}

func NewService(hm Hosting, cfg *alaye.Gossip, logger *ll.Logger) (*Service, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	s := &Service{
		hm:          hm,
		logger:      logger,
		authTimeout: woos.DefaultAuthTimeout,
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
	c.Name = woos.MemberlistNamePrefix + c.Name

	c.BindPort = cfg.Port
	if c.BindPort == 0 {
		c.BindPort = woos.DefaultGossipPort
	}

	if cfg.SecretKey != "" {
		key := []byte(cfg.SecretKey)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, woos.ErrInvalidSecretKey
		}
		c.SecretKey = key
	}

	c.PushPullInterval = woos.DefaultPushPullInterval
	s.localName = c.Name
	c.Events = &event{s: s}
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
