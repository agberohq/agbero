package cluster

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

type delegate struct {
	mu    sync.RWMutex
	store map[string]Envelope

	queue   *memberlist.TransmitLimitedQueue
	handler UpdateHandler
	logger  *ll.Logger
}

func newDelegate(handler UpdateHandler, logger *ll.Logger) *delegate {
	return &delegate{
		store:   make(map[string]Envelope),
		handler: handler,
		logger:  logger,
	}
}

func (d *delegate) setQueue(q *memberlist.TransmitLimitedQueue) {
	d.queue = q
}

// NodeMeta is used to validate nodes joining the cluster
func (d *delegate) NodeMeta(limit int) []byte {
	return []byte("{}")
}

// NotifyMsg is called when a user-data message is received
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

// GetBroadcasts is called when sending a gossip packet
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.queue.GetBroadcasts(overhead, limit)
}

// LocalState is called during Push/Pull sync
func (d *delegate) LocalState(join bool) []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	b, _ := json.Marshal(d.store)
	return b
}

// MergeRemoteState is called when we receive a full state sync
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

// apply handles Last-Writer-Wins logic
func (d *delegate) apply(env Envelope, local bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	existing, exists := d.store[env.Key]

	// Conflict Resolution: LWW (Last Writer Wins)
	if exists && existing.Timestamp >= env.Timestamp {
		return
	}

	// Apply update
	d.store[env.Key] = env

	// Notify system
	if d.handler != nil {
		isDelete := env.Op == OpDel
		d.handler.OnClusterChange(env.Key, env.Value, isDelete)
	}

	// If this update came from us (local), broadcast it.
	// If it came from remote, memberlist gossip protocol handles re-propagation.
	if local && d.queue != nil {
		d.queue.QueueBroadcast(&peerUpdate{env: env})
	}
}

// Direct access methods for the Manager
func (d *delegate) set(key string, value []byte) {
	env := Envelope{
		Op:        OpSet,
		Key:       key,
		Value:     value,
		Timestamp: time.Now().UnixNano(),
	}
	d.apply(env, true)
}

func (d *delegate) delete(key string) {
	env := Envelope{
		Op:        OpDel,
		Key:       key,
		Value:     nil,
		Timestamp: time.Now().UnixNano(),
	}
	d.apply(env, true)
}

func (d *delegate) get(key string) ([]byte, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	env, ok := d.store[key]
	if !ok || env.Op == OpDel {
		return nil, false
	}
	return env.Value, true
}
