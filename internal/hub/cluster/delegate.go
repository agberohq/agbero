package cluster

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/zero"
)

const (
	tombstoneTTL = 24 * time.Hour
	lockTTL      = 60 * time.Second
	challengeTTL = 15 * time.Minute
)

type delegate struct {
	mu             sync.RWMutex
	store          map[string]Envelope
	queue          *memberlist.TransmitLimitedQueue
	handler        UpdateHandler
	logger         *ll.Logger
	metrics        Metrics
	cipher         *security.Cipher
	configMgr      *Distributor
	keeperSnapshot func() map[string][]byte
	keeperWrite    func(key string, value []byte)
}

// newDelegate initializes the state manager for gossip events.
// It handles conflict resolution, payload decryption, and local application.
func newDelegate(cfg Config, handler UpdateHandler, logger *ll.Logger, metrics Metrics, cipher *security.Cipher, configMgr *Distributor) *delegate {
	if metrics == nil {
		metrics = &RealMetrics{}
	}
	return &delegate{
		store:          make(map[string]Envelope),
		handler:        handler,
		logger:         logger,
		metrics:        metrics,
		cipher:         cipher,
		configMgr:      configMgr,
		keeperSnapshot: cfg.KeeperSnapshot,
		keeperWrite:    cfg.KeeperWrite,
	}
}

// NodeMeta is required by memberlist to share node metadata.
// Currently returns an empty JSON object.
func (d *delegate) NodeMeta(limit int) []byte {
	return []byte("{}")
}

// NotifyMsg triggers when a cluster message is received.
// Unmarshals the envelope and routes it to the application logic.
func (d *delegate) NotifyMsg(b []byte) {
	if len(b) == 0 {
		return
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		d.logger.Error("cluster: failed to unmarshal msg", "err", err)
		return
	}
	d.apply(env, false)
}

// GetBroadcasts pulls pending updates for gossip dissemination.
// memberlist calls this during background gossip rounds.
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.queue == nil {
		return nil
	}
	return d.queue.GetBroadcasts(overhead, limit)
}

// LocalState generates a complete snapshot of local state.
// Triggered when a new node attempts a full sync during join.
func (d *delegate) LocalState(join bool) []byte {
	// Snapshot the gossip store under the read lock, then release before doing
	// anything that touches external state (keeper). Holding d.mu across a keeper
	// call would risk a cross-lock deadlock if keeper ever calls back into cluster.
	d.mu.RLock()
	storeCopy := make(map[string]Envelope, len(d.store))
	for k, v := range d.store {
		storeCopy[k] = v
	}
	d.mu.RUnlock()

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}

	doc := stateDoc{Store: storeCopy}

	// When a new node is joining, include encrypted keeper secrets so it is
	// immediately authentication-compatible without any operator intervention.
	if join && d.keeperSnapshot != nil && d.cipher != nil {
		snapshot := d.keeperSnapshot()
		now := time.Now().UnixNano()
		for key, plaintext := range snapshot {
			encrypted, err := d.cipher.Encrypt(plaintext)
			zero.Bytes(plaintext)
			if err != nil {
				d.logger.Error("cluster: failed to encrypt secret for join sync", "key", key, "err", err)
				continue
			}
			doc.Secrets = append(doc.Secrets, Envelope{
				Op:        OpSecret,
				Key:       key,
				Value:     encrypted,
				Timestamp: now,
			})
		}
		if len(doc.Secrets) > 0 {
			d.logger.Info("cluster: including keeper secrets in join state", "count", len(doc.Secrets))
		}
	}

	b, err := json.Marshal(doc)
	if err != nil {
		d.logger.Error("cluster: failed to marshal local state", "err", err)
		return []byte("{}")
	}
	return b
}

// MergeRemoteState reconciles incoming state snapshots with local data.
// Safely integrates historical updates observed from peers.
func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	if len(buf) == 0 {
		return
	}

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}

	var doc stateDoc
	if err := json.Unmarshal(buf, &doc); err != nil {
		d.logger.Error("cluster: failed to unmarshal remote state", "err", err)
		return
	}

	// Backward compatibility: nodes running the old code send a flat map
	// {"key": Envelope, ...} rather than {"store": {...}, "secrets": [...]}.
	// When doc.Store is nil but the buffer is non-empty JSON, try the old format.
	if doc.Store == nil && len(doc.Secrets) == 0 {
		var legacy map[string]Envelope
		if err := json.Unmarshal(buf, &legacy); err == nil && len(legacy) > 0 {
			for _, env := range legacy {
				d.apply(env, false)
			}
			return
		}
	}

	// Apply regular gossip state entries.
	for _, env := range doc.Store {
		d.apply(env, false)
	}

	// Apply encrypted keeper secrets — only present on join from a new-format node.
	if len(doc.Secrets) > 0 {
		if d.cipher == nil {
			d.logger.Warn("cluster: received keeper secrets but no cipher available — secrets dropped; ensure secret_key is configured")
		} else if d.keeperWrite == nil {
			d.logger.Warn("cluster: received keeper secrets but no keeper write handler — secrets dropped")
		} else {
			applied := 0
			for _, env := range doc.Secrets {
				if env.Op != OpSecret || len(env.Value) == 0 {
					continue
				}
				plaintext, err := d.cipher.Decrypt(env.Value)
				if err != nil {
					d.logger.Error("cluster: failed to decrypt secret", "key", env.Key, "err", err)
					continue
				}
				d.keeperWrite(env.Key, plaintext)
				zero.Bytes(plaintext)
				applied++
			}
			d.logger.Info("cluster: applied keeper secrets from join sync", "count", applied)
		}
	}
}

func (d *delegate) apply(env Envelope, local bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.metrics.IncUpdatesReceived()

	age := time.Duration(time.Now().UnixNano() - env.Timestamp)
	if age > tombstoneTTL {
		d.logger.Debug("cluster: discarding stale envelope", "key", env.Key, "age", age)
		d.metrics.IncUpdatesIgnored()
		return
	}

	existing, exists := d.store[env.Key]
	shouldApply := false
	if env.Op == OpLock {
		if exists {
			if time.Since(time.Unix(0, existing.Timestamp)) > lockTTL {
				shouldApply = true
			} else if env.Timestamp < existing.Timestamp {
				shouldApply = true
			}
		} else {
			shouldApply = true
		}
	} else {
		if !exists || env.Timestamp > existing.Timestamp {
			shouldApply = true
		}
	}
	if !shouldApply {
		d.metrics.IncUpdatesIgnored()
		return
	}
	if env.Op == OpDel {
		env.Value = nil
		d.metrics.IncDeletes()
	}
	d.store[env.Key] = env
	if d.handler != nil {
		switch env.Op {
		case OpCert:
			d.handleCertUpdate(env)
		case OpChallenge:
			token := env.Key[5:]
			keyAuth := string(env.Value)
			d.handler.OnClusterChallenge(token, keyAuth, env.Op == OpDel)
		case OpRoute, OpSet, OpDel:
			d.handler.OnClusterChange(env.Key, env.Value, env.Op == OpDel)
		case OpStatus:
			d.logger.Fields("node", env.Owner, "status", string(env.Value)).Debug("cluster node status change")
		case OpConfig:
			d.handleConfigUpdate(env)
		}
	}
	if local && d.queue != nil {
		if env.Op != OpConfig && env.Op != OpCert {
			d.queue.QueueBroadcast(&peerUpdate{env: env})
		}
	}
}

// handleCertUpdate processes a certificate payload.
// Decrypts the private key and delegates the certificate installation.
func (d *delegate) handleCertUpdate(env Envelope) {
	var payload CertPayload
	if err := json.Unmarshal(env.Value, &payload); err != nil {
		d.logger.Error("cluster: failed to unmarshal cert payload", "err", err)
		return
	}
	if d.cipher == nil {
		d.logger.Warn("cluster: received cert but no cipher available to decrypt")
		return
	}
	decryptedKey, err := d.cipher.Decrypt(payload.KeyPEM)
	if err != nil {
		d.logger.Error("cluster: failed to decrypt private key", "err", err)
		return
	}
	if err := d.handler.OnClusterCert(payload.Domain, payload.CertPEM, decryptedKey); err != nil {
		d.logger.Error("cluster: failed to apply cert", "err", err)
	} else {
		d.logger.Info("cluster: synced certificate", "domain", payload.Domain)
	}
}

// handleConfigUpdate processes configuration file syncs.
// Defers to the dedicated config manager for disk operations and validation.
func (d *delegate) handleConfigUpdate(env Envelope) {
	if d.configMgr != nil {
		var payload ConfigPayload
		if err := json.Unmarshal(env.Value, &payload); err != nil {
			d.logger.Fields("err", err, "sender", env.Owner).Error("cluster: failed to unmarshal config payload")
			return
		}
		d.configMgr.Apply(payload)
		return
	}
	if d.handler == nil {
		return
	}
	type configHandler interface {
		OnClusterConfigChange(domain string, rawHCL []byte, deleted bool)
	}
	if ch, ok := d.handler.(configHandler); ok {
		var payload ConfigPayload
		if err := json.Unmarshal(env.Value, &payload); err != nil {
			d.logger.Fields("err", err, "sender", env.Owner).Error("cluster: failed to unmarshal config payload")
			return
		}
		ch.OnClusterConfigChange(payload.Domain, payload.RawHCL, payload.Deleted)
	}
}

// pruneTombstones clears expired state records from memory.
// Prevents indefinitely growing state trees from removed or temporary data.
func (d *delegate) pruneTombstones() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UnixNano()
	for k, env := range d.store {
		age := time.Duration(now - env.Timestamp)
		if env.Op == OpDel {
			if age > tombstoneTTL {
				delete(d.store, k)
			}
		} else if env.Op == OpLock {
			if age > lockTTL {
				delete(d.store, k)
			}
		} else if env.Op == OpChallenge {
			if age > challengeTTL {
				delete(d.store, k)
			}
		}
	}
}

func (d *delegate) get(key string) ([]byte, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	env, ok := d.store[key]
	if !ok || env.Op == OpDel {
		return nil, false
	}
	if env.Op == OpLock && time.Since(time.Unix(0, env.Timestamp)) > lockTTL {
		return nil, false
	}
	if env.Op == OpChallenge && time.Since(time.Unix(0, env.Timestamp)) > challengeTTL {
		return nil, false
	}
	return env.Value, true
}

// getEnvelope extracts the full data wrapper for inspection.
// Used for internal lock validation and timestamp checks.
func (d *delegate) getEnvelope(key string) (Envelope, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	env, ok := d.store[key]
	return env, ok
}
