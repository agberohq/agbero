package cluster

import (
	"encoding/json"

	"github.com/hashicorp/memberlist"
)

// Cluster defines the distributed backend contract for cloud-native readiness.
// Implementations (Memberlist, ETCD, Consul) must satisfy these coordination primitives.
type Cluster interface {
	Members() []string
	Get(key string) ([]byte, bool)
	Set(key string, value []byte)
	Delete(key string)
	TryAcquireLock(key string) bool

	BroadcastCert(domain string, certPEM, keyPEM []byte) error
	BroadcastConfig(domain string, rawHCL []byte, deleted bool) error
	BroadcastChallenge(token, keyAuth string, deleted bool)

	Shutdown() error
}

type OpType uint8

const (
	OpSet       OpType = 1
	OpDel       OpType = 2
	OpRoute     OpType = 3
	OpCert      OpType = 4
	OpLock      OpType = 5
	OpStatus    OpType = 6
	OpChallenge OpType = 7
	OpConfig    OpType = 8
)

type Envelope struct {
	Op        OpType `json:"op"`
	Key       string `json:"k"`
	Value     []byte `json:"v,omitempty"`
	Timestamp int64  `json:"ts"`
	Owner     string `json:"owner,omitempty"`
}

type CertPayload struct {
	Domain  string `json:"domain"`
	CertPEM []byte `json:"cert"`
	KeyPEM  []byte `json:"key"`
}

type ConfigPayload struct {
	Domain    string `json:"domain"`
	RawHCL    []byte `json:"raw_hcl,omitempty"`
	Checksum  string `json:"checksum"`
	Timestamp int64  `json:"timestamp"`
	NodeID    string `json:"node_id"`
	Deleted   bool   `json:"deleted"`
}

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
