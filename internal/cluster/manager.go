// internal/cluster/manager.go
package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

const (
	pruneInterval   = 30 * time.Second
	fullSyncDelay   = 2 * time.Second
	leaveTimeout    = 5 * time.Second
	shutdownTimeout = 5 * time.Second
)

type Config struct {
	BindAddr string
	BindPort int
	Secret   []byte
	Name     string
	Seeds    []string
	HostsDir string
}

type Manager struct {
	list      *memberlist.Memberlist
	delegate  *delegate
	events    *eventDelegate
	logger    *ll.Logger
	metrics   Metrics
	stopCh    chan struct{}
	cipher    *security.Cipher
	configMgr *ConfigManager
	nodeName  string
}

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
	mConfig.Logger = log.New(io.Discard, "", 0)
	var cipher *security.Cipher
	if len(cfg.Secret) > 0 {
		var err error
		cipher, err = security.NewCipher(string(cfg.Secret))
		if err != nil {
			return nil, fmt.Errorf("failed to create cluster payload cipher: %w", err)
		}
	}
	configMgr := NewConfigManager(cfg.HostsDir, logger)
	metrics := NewMetrics()
	del := newDelegate(handler, logger, metrics, cipher, configMgr)
	events := &eventDelegate{logger: logger, metrics: metrics}
	mConfig.Delegate = del
	mConfig.Events = events
	list, err := memberlist.Create(mConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}
	queue := &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return list.NumMembers() },
		RetransmitMult: 3,
	}
	del.mu.Lock()
	del.queue = queue
	del.mu.Unlock()
	mgr := &Manager{
		list:      list,
		delegate:  del,
		events:    events,
		logger:    logger,
		metrics:   metrics,
		stopCh:    make(chan struct{}),
		cipher:    cipher,
		configMgr: configMgr,
		nodeName:  cfg.Name,
	}
	mgr.BroadcastStatus("active")
	if len(cfg.Seeds) > 0 {
		count, err := list.Join(cfg.Seeds)
		if err != nil {
			logger.Warn("failed to join cluster seeds", "err", err, "seeds", cfg.Seeds)
		} else {
			logger.Info("joined cluster", "nodes", count)
			go mgr.triggerFullSync()
		}
	}
	go mgr.maintenanceLoop()
	return mgr, nil
}

func (m *Manager) triggerFullSync() {
	time.Sleep(fullSyncDelay)
	members := m.list.Members()
	for _, node := range members {
		if node.Name != m.nodeName {
			addr := memberlist.Address{Addr: node.Address(), Name: node.Name}
			err := m.list.PushPullNode(addr, true)
			if err == nil {
				m.logger.Info("successfully synced state from cluster peer", "peer", node.Name)
				break
			}
		}
	}
}

func (m *Manager) maintenanceLoop() {
	ticker := time.NewTicker(pruneInterval)
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

func (m *Manager) TryAcquireLock(key string) bool {
	lockKey := "lock:" + key
	myID := m.nodeName
	if myID == "" {
		myID, _ = os.Hostname()
	}
	if env, ok := m.delegate.getEnvelope(lockKey); ok {
		if env.Owner != myID && time.Since(time.Unix(0, env.Timestamp)) < lockTTL {
			return false
		}
	}
	m.delegate.broadcast(OpLock, lockKey, []byte("claimed"), myID)
	time.Sleep(2 * time.Second)
	if env, ok := m.delegate.getEnvelope(lockKey); ok {
		if env.Owner == myID {
			return true
		}
	}
	return false
}

func (m *Manager) BroadcastCert(domain string, certPEM, keyPEM []byte) error {
	if m.cipher == nil {
		return fmt.Errorf("cluster encryption not enabled, cannot broadcast certs")
	}
	encryptedKey, err := m.cipher.Encrypt(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}
	payload := CertPayload{
		Domain:  domain,
		CertPEM: certPEM,
		KeyPEM:  encryptedKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	m.delegate.broadcast(OpCert, "cert:"+domain, data, m.nodeName)
	return nil
}

func (m *Manager) BroadcastConfig(domain string, rawHCL []byte, deleted bool) error {
	return m.configMgr.LoadAndBroadcast(domain, rawHCL, deleted, m.nodeName, m.delegate)
}

func (m *Manager) BroadcastChallenge(token, keyAuth string, deleted bool) {
	key := "acme:" + token
	if deleted {
		m.delegate.broadcast(OpDel, key, nil, m.nodeName)
	} else {
		m.delegate.broadcast(OpChallenge, key, []byte(keyAuth), m.nodeName)
	}
}

func (m *Manager) BroadcastRoute(key string, value []byte) {
	m.delegate.broadcast(OpRoute, key, value, m.nodeName)
}

func (m *Manager) BroadcastStatus(status string) {
	key := "status:" + m.nodeName
	m.delegate.broadcast(OpStatus, key, []byte(status), m.nodeName)
}

func (m *Manager) Set(key string, value []byte) {
	m.delegate.broadcast(OpSet, key, value, m.nodeName)
}

func (m *Manager) Delete(key string) {
	m.delegate.broadcast(OpDel, key, nil, m.nodeName)
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

func (m *Manager) Metrics() map[string]uint64 {
	return m.metrics.Snapshot()
}

func (m *Manager) ConfigManager() *ConfigManager {
	return m.configMgr
}

func (m *Manager) Shutdown() error {
	close(m.stopCh)
	m.BroadcastStatus("offline")
	if err := m.list.Leave(leaveTimeout); err != nil {
		m.logger.Warn("cluster leave failed", "err", err)
	}
	return m.list.Shutdown()
}
