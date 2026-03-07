package cluster

import (
	"encoding/json"

	"github.com/hashicorp/memberlist"
)

type OpType uint8

const (
	OpSet       OpType = 1
	OpDel       OpType = 2
	OpRoute     OpType = 3
	OpCert      OpType = 4
	OpLock      OpType = 5
	OpStatus    OpType = 6
	OpChallenge OpType = 7 // ACME HTTP-01 Challenge Token
)

// Envelope is the generic container for gossip messages
type Envelope struct {
	Op        OpType `json:"op"`
	Key       string `json:"k"`
	Value     []byte `json:"v,omitempty"`
	Timestamp int64  `json:"ts"`
	Owner     string `json:"owner,omitempty"`
}

// CertPayload is the specific payload for certificate updates.
type CertPayload struct {
	Domain  string `json:"domain"`
	CertPEM []byte `json:"cert"`
	KeyPEM  []byte `json:"key"` // Encrypted
}

// UpdateHandler defines how the cluster notifies other components
type UpdateHandler interface {
	OnClusterChange(key string, value []byte, deleted bool)
	OnClusterCert(domain string, certPEM, keyPEM []byte) error
	OnClusterChallenge(token, keyAuth string, deleted bool)
}

type peerUpdate struct {
	env Envelope
}

func (p *peerUpdate) Invalidates(other memberlist.Broadcast) bool {
	if o, ok := other.(*peerUpdate); ok {
		return p.env.Key == o.env.Key && p.env.Timestamp > o.env.Timestamp
	}
	return false
}

func (p *peerUpdate) Message() []byte {
	b, _ := json.Marshal(p.env)
	return b
}

func (p *peerUpdate) Finished() {}
