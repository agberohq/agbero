package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
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
	HostsDir expect.Folder

	// KeeperSnapshot is called by the seed node during LocalState(join=true) to
	// collect all keeper secrets that should be pushed to the joining node.
	// The returned map is key -> plaintext bytes; values are zeroed after use.
	// Nil means no keeper sync.
	KeeperSnapshot func() map[string][]byte

	// KeeperWrite is called on the joining node when an OpSecret envelope arrives
	// via MergeRemoteState. It must write key -> value into the local keeper store.
	// The value slice is zeroed by the caller immediately after KeeperWrite returns.
	// Nil means incoming OpSecret envelopes are dropped.
	KeeperWrite func(key string, value []byte)
}

type Manager struct {
	list      *memberlist.Memberlist
	delegate  *delegate
	events    *eventDelegate
	logger    *ll.Logger
	metrics   Metrics
	stopCh    chan struct{}
	cipher    *security.Cipher
	configMgr *Distributor
	nodeName  string
}

type eventDelegate struct {
	logger  *ll.Logger
	metrics Metrics
}

func (e *eventDelegate) NotifyJoin(n *memberlist.Node) {
	e.metrics.IncJoin()
	e.logger.Info("node joined cluster", "node", n.Name, "addr", n.Addr, "port", n.Port)
}

func (e *eventDelegate) NotifyLeave(n *memberlist.Node) {
	e.metrics.IncLeave()
	e.logger.Info("node left cluster", "node", n.Name, "port", n.Port)
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

	configMgr := NewDistributor(logger, cfg.HostsDir)
	metrics := NewMetrics()
	del := newDelegate(cfg, handler, logger, metrics, cipher, configMgr)
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
		}
	}

	go mgr.maintenanceLoop()
	return mgr, nil
}

// maintenanceLoop runs periodically to trigger state pruning.
// Ensures memory isn't leaked over time by expired records.
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

// BroadcastReliable sends a payload to all cluster members over TCP.
// It guarantees delivery for critical data like configurations and certificates.
func (m *Manager) BroadcastReliable(op OpType, key string, value []byte) error {
	env := Envelope{
		Op:        op,
		Key:       key,
		Value:     value,
		Owner:     m.nodeName,
		Timestamp: time.Now().UnixNano(),
	}
	m.delegate.apply(env, true)
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}

	if m.list == nil {
		return nil
	}
	for _, node := range m.list.Members() {
		if node.Name != m.nodeName {
			_ = m.list.SendReliable(node, data)
		}
	}
	return nil
}

// BroadcastSecret encrypts plaintext with the cluster cipher and broadcasts
// it to all peers as an OpSecret envelope. Peers handle it in apply() and
// write it to their local keeper via keeperWrite.
// This is called by the keeper API handler after any write or delete so that
// runtime secret changes propagate to all cluster nodes.
func (m *Manager) BroadcastSecret(key string, plaintext []byte) error {
	if m.delegate.cipher == nil {
		return fmt.Errorf("cluster: no cipher configured — secret_key missing from gossip block")
	}
	var value []byte
	if len(plaintext) > 0 {
		encrypted, err := m.delegate.cipher.Encrypt(plaintext)
		if err != nil {
			return fmt.Errorf("cluster: encrypt secret %q: %w", key, err)
		}
		value = encrypted
	}
	m.BroadcastGossip(OpSecret, key, value)
	return nil
}

func (m *Manager) BroadcastGossip(op OpType, key string, value []byte) {
	env := Envelope{
		Op:        op,
		Key:       key,
		Value:     value,
		Owner:     m.nodeName,
		Timestamp: time.Now().UnixNano(),
	}
	m.delegate.apply(env, true)
}

// TryAcquireLock attempts to grab a distributed lock over the gossip layer.
// Useful for ensuring single-node operations (like ACME issuance) in a cluster.
func (m *Manager) TryAcquireLock(key string) bool {
	lockKey := "lock:" + key
	myID := m.nodeName
	if myID == "" {
		myID, _ = os.Hostname()
	}

	// Reject immediately if another node holds a live lock.
	if env, ok := m.delegate.getEnvelope(lockKey); ok {
		if env.Owner != myID && time.Since(time.Unix(0, env.Timestamp)) < lockTTL {
			return false
		}
	}

	m.BroadcastGossip(OpLock, lockKey, []byte("claimed"))
	time.Sleep(2 * time.Second)

	if env, ok := m.delegate.getEnvelope(lockKey); ok {
		return env.Owner == myID
	}
	return false
}

// BroadcastCert encrypts and disseminates new SSL certificates reliably.
// Prevents multiple nodes from hammering Let's Encrypt simultaneously.
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
	return m.BroadcastReliable(OpCert, "cert:"+domain, data)
}

// BroadcastConfig propagates a host configuration file to the cluster.
// It utilizes TCP to bypass standard gossip UDP payload limits.
func (m *Manager) BroadcastConfig(domain string, rawHCL []byte, deleted bool) error {
	payload, err := m.configMgr.PreparePayload(domain, rawHCL, deleted, m.nodeName)
	if err != nil || payload == nil {
		return err
	}
	payload.Timestamp = time.Now().UnixNano()
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.BroadcastReliable(OpConfig, "config:"+domain, data)
}

// BroadcastChallenge disseminates ACME tokens for HTTP-01 verification.
// Allows any node behind the load balancer to answer validation requests.
func (m *Manager) BroadcastChallenge(token, keyAuth string, deleted bool) {
	key := "acme:" + token
	if deleted {
		m.BroadcastGossip(OpDel, key, nil)
	} else {
		m.BroadcastGossip(OpChallenge, key, []byte(keyAuth))
	}
}

// BroadcastRoute distributes ephemeral routing logic over UDP.
// Commonly used for temporary webhook or API-created paths.
func (m *Manager) BroadcastRoute(key string, value []byte) {
	m.BroadcastGossip(OpRoute, key, value)
}

// BroadcastStatus shares health and readiness states across peers.
// Enables traffic shaping and early aborts based on neighbor status.
func (m *Manager) BroadcastStatus(status string) {
	key := "status:" + m.nodeName
	m.BroadcastGossip(OpStatus, key, []byte(status))
}

// Set persists a generic key-value pair into the gossip mesh.
func (m *Manager) Set(key string, value []byte) {
	m.BroadcastGossip(OpSet, key, value)
}

// Delete removes a key from the gossip mesh globally.
func (m *Manager) Delete(key string) {
	m.BroadcastGossip(OpDel, key, nil)
}

// Get returns the value of a key from the local cache.
func (m *Manager) Get(key string) ([]byte, bool) {
	return m.delegate.get(key)
}

// Members returns a list of actively connected node names.
func (m *Manager) Members() []string {
	members := m.list.Members()
	names := make([]string, len(members))
	for i, n := range members {
		names[i] = n.Name
	}
	return names
}

// Metrics retrieves operation counts for monitoring hooks.
func (m *Manager) Metrics() map[string]uint64 {
	return m.metrics.Snapshot()
}

func (m *Manager) ConfigManager() *Distributor {
	return m.configMgr
}

// Shutdown safely disconnects the node and alerts peers before exit.
// Stops maintenance loops to free resources gracefully.
func (m *Manager) Shutdown() error {
	close(m.stopCh)
	m.BroadcastStatus("offline")
	if err := m.list.Leave(leaveTimeout); err != nil {
		m.logger.Warn("cluster leave failed", "err", err)
	}
	return m.list.Shutdown()
}
