package firewall

import (
	"time"
)

type BlockType uint8

const (
	BlockTypeSingle BlockType = 0
	BlockTypeCIDR   BlockType = 1
)

type Rule struct {
	IP        string    `json:"ip"` // string representation for JSON
	Type      BlockType `json:"type"`
	Host      string    `json:"host,omitempty"`
	Path      string    `json:"path,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Zero time = permanent

}

// IsExpired checks if the rule is past its TTL
func (r *Rule) IsExpired() bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(r.ExpiresAt)
}
