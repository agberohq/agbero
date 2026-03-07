package cluster

import (
	"encoding/json"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

const (
	tombstoneTTL = 24 * time.Hour
	lockTTL      = 60 * time.Second
	challengeTTL = 15 * time.Minute // Short TTL for ACME tokens
)

type delegate struct {
	mu    sync.RWMutex
	store map[string]Envelope

	queue   *memberlist.TransmitLimitedQueue
	handler UpdateHandler
	logger  *ll.Logger
	metrics Metrics
	cipher  *security.Cipher
}

func newDelegate(handler UpdateHandler, logger *ll.Logger, metrics Metrics, cipher *security.Cipher) *delegate {
	if metrics == nil {
		metrics = &RealMetrics{}
	}
	return &delegate{
		store:   make(map[string]Envelope),
		handler: handler,
		logger:  logger,
		metrics: metrics,
		cipher:  cipher,
	}
}

func (d *delegate) NodeMeta(limit int) []byte {
	return []byte("{}")
}

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

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.queue == nil {
		return nil
	}
	return d.queue.GetBroadcasts(overhead, limit)
}

func (d *delegate) LocalState(join bool) []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	b, err := json.Marshal(d.store)
	if err != nil {
		d.logger.Error("cluster: failed to marshal local state", "err", err)
		return []byte("{}")
	}
	return b
}

func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	if len(buf) == 0 {
		return
	}

	var remote map[string]Envelope
	if err := json.Unmarshal(buf, &remote); err != nil {
		d.logger.Error("cluster: failed to unmarshal remote state", "err", err)
		return
	}

	for _, env := range remote {
		d.apply(env, false)
	}
}

func (d *delegate) apply(env Envelope, local bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.metrics.IncUpdatesReceived()

	existing, exists := d.store[env.Key]

	shouldApply := false

	if env.Op == OpLock {
		if exists {
			if time.Since(time.Unix(0, existing.Timestamp)) > lockTTL {
				shouldApply = true
			} else {
				if env.Timestamp < existing.Timestamp {
					shouldApply = true
				}
			}
		} else {
			shouldApply = true
		}
	} else {
		// Standard LWW
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
			// Key is "acme:TOKEN", Value is KeyAuth
			token := env.Key[5:] // remove "acme:"
			keyAuth := string(env.Value)
			d.handler.OnClusterChallenge(token, keyAuth, env.Op == OpDel)
		case OpRoute, OpSet, OpDel:
			d.handler.OnClusterChange(env.Key, env.Value, env.Op == OpDel)
		case OpStatus:
			d.logger.Fields("node", env.Owner, "status", string(env.Value)).Debug("cluster node status change")
		}
	}

	if local && d.queue != nil {
		d.queue.QueueBroadcast(&peerUpdate{env: env})
	}
}

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

func (d *delegate) broadcast(op OpType, key string, value []byte, owner string) {
	env := Envelope{
		Op:        op,
		Key:       key,
		Value:     value,
		Owner:     owner,
		Timestamp: time.Now().UnixNano(),
	}
	d.apply(env, true)
}

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

func (d *delegate) getEnvelope(key string) (Envelope, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	env, ok := d.store[key]
	return env, ok
}
