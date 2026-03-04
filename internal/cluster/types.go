package cluster

import (
	"encoding/json"

	"github.com/hashicorp/memberlist"
)

type OpType uint8

const (
	OpSet OpType = 1
	OpDel OpType = 2
)

type Envelope struct {
	Op        OpType `json:"op"`
	Key       string `json:"k"`
	Value     []byte `json:"v,omitempty"`
	Timestamp int64  `json:"ts"` // UnixNano for LWW resolution
}

type UpdateHandler interface {
	OnClusterChange(key string, value []byte, deleted bool)
}

type peerUpdate struct {
	env Envelope
}

func (p *peerUpdate) Invalidates(other memberlist.Broadcast) bool {
	// Optimistic check: if we are broadcasting a newer version of the same key,
	// we invalidate the older broadcast.
	if o, ok := other.(*peerUpdate); ok {
		return p.env.Key == o.env.Key && p.env.Timestamp > o.env.Timestamp
	}
	return false
}

func (p *peerUpdate) Message() []byte {
	// Simple JSON serialization for the broadcast message
	// In production high-load, msgpack/protobuf is preferred, keeping JSON for readability now
	b, _ := json.Marshal(p.env)
	return b
}

func (p *peerUpdate) Finished() {}
