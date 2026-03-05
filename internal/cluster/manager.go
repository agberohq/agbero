package cluster

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

type Config struct {
	BindAddr string
	BindPort int
	Secret   []byte
	Name     string
	Seeds    []string
}

type Manager struct {
	list     *memberlist.Memberlist
	delegate *delegate
	events   *eventDelegate
	logger   *ll.Logger
	stopCh   chan struct{}
}

// eventDelegate handles Node Join/Leave logs
type eventDelegate struct {
	logger  *ll.Logger
	metrics Metrics
}

func (e *eventDelegate) NotifyJoin(n *memberlist.Node) {
	e.metrics.IncJoin()
	e.logger.Info("node joined cluster", "node", n.Name, "addr", n.Addr)
}
func (e *eventDelegate) NotifyLeave(n *memberlist.Node) {
	e.metrics.IncLeave()
	e.logger.Info("node left cluster", "node", n.Name)
}
func (e *eventDelegate) NotifyUpdate(n *memberlist.Node) {}

func NewManager(cfg Config, handler UpdateHandler, logger *ll.Logger) (*Manager, error) {
	mConfig := memberlist.DefaultLANConfig()
	mConfig.Name = cfg.Name
	mConfig.BindAddr = cfg.BindAddr
	mConfig.BindPort = cfg.BindPort

	if len(cfg.Secret) > 0 {
		mConfig.SecretKey = cfg.Secret
	}

	// Quiet down standard memberlist logging
	mConfig.Logger = log.New(io.Discard, "", 0)

	// In a real scenario, you'd pass a real metrics collector here
	metrics := &noopMetrics{}

	del := newDelegate(handler, logger, metrics)
	events := &eventDelegate{logger: logger, metrics: metrics}

	mConfig.Delegate = del
	mConfig.Events = events

	list, err := memberlist.Create(mConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}

	// Initialize queue safely after list creation
	queue := &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return list.NumMembers() },
		RetransmitMult: 3,
	}

	// Delegate owns the queue, but we set it here where it's safe
	del.mu.Lock()
	del.queue = queue
	del.mu.Unlock()

	mgr := &Manager{
		list:     list,
		delegate: del,
		events:   events,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	if len(cfg.Seeds) > 0 {
		count, err := list.Join(cfg.Seeds)
		if err != nil {
			logger.Warn("failed to join cluster seeds", "err", err, "seeds", cfg.Seeds)
		} else {
			logger.Info("joined cluster", "nodes", count)
		}
	}

	go mgr.maintenanceLoop()

	return mgr, nil
}

func (m *Manager) maintenanceLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.delegate.pruneTombstones()
		}
	}
}

func (m *Manager) Set(key string, value []byte) {
	m.delegate.set(key, value)
}

func (m *Manager) Delete(key string) {
	m.delegate.delete(key)
}

func (m *Manager) Get(key string) ([]byte, bool) {
	return m.delegate.get(key)
}

func (m *Manager) Members() []string {
	members := m.list.Members()
	names := make([]string, len(members))
	for i, n := range members {
		names[i] = n.Name
	}
	return names
}

func (m *Manager) Shutdown() error {
	close(m.stopCh)
	// Leave politely
	if err := m.list.Leave(5 * time.Second); err != nil {
		m.logger.Warn("cluster leave failed", "err", err)
	}
	return m.list.Shutdown()
}
