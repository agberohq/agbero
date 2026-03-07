package tlss

import (
	"sync"

	"github.com/olekukonko/ll"
)

type ChallengeProvider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

type ChallengeStore struct {
	mu      sync.RWMutex
	tokens  map[string]string // token -> keyAuth
	cluster ClusterBroadcaster
	logger  *ll.Logger
}

type ClusterBroadcaster interface {
	BroadcastChallenge(token, keyAuth string, deleted bool)
}

func NewChallengeStore(logger *ll.Logger) *ChallengeStore {
	return &ChallengeStore{
		tokens: make(map[string]string),
		logger: logger.Namespace("acme"),
	}
}

func (s *ChallengeStore) SetCluster(c ClusterBroadcaster) {
	s.cluster = c
}

// Present implements the ACME Challenge Provider interface (for Lego).
// It stores the token locally and broadcasts it to the cluster.
func (s *ChallengeStore) Present(domain, token, keyAuth string) error {
	s.mu.Lock()
	s.tokens[token] = keyAuth
	s.mu.Unlock()

	s.logger.Fields("domain", domain, "token", token).Info("presenting acme challenge")

	if s.cluster != nil {
		s.cluster.BroadcastChallenge(token, keyAuth, false)
	}
	return nil
}

// CleanUp removes the token locally and broadcasts deletion.
func (s *ChallengeStore) CleanUp(domain, token, keyAuth string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()

	if s.cluster != nil {
		s.cluster.BroadcastChallenge(token, keyAuth, true)
	}
	return nil
}

// GetKeyAuth retrieves the key authorization for a given token.
// Used by the HTTP handler to respond to Let's Encrypt.
func (s *ChallengeStore) GetKeyAuth(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.tokens[token]
	return val, ok
}

// SyncFromCluster is called when a peer adds/removes a challenge via Gossip.
func (s *ChallengeStore) SyncFromCluster(token, keyAuth string, deleted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if deleted {
		delete(s.tokens, token)
	} else {
		s.tokens[token] = keyAuth
	}
}
