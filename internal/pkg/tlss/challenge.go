package tlss

import (
	"sync"

	"github.com/olekukonko/ll"
)

type ClusterBroadcaster interface {
	BroadcastChallenge(token, keyAuth string, deleted bool)
}

type ChallengeStore struct {
	mu      sync.RWMutex
	tokens  map[string]string
	cluster ClusterBroadcaster
	logger  *ll.Logger
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

func (s *ChallengeStore) CleanUp(domain, token, keyAuth string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()

	if s.cluster != nil {
		s.cluster.BroadcastChallenge(token, keyAuth, true)
	}
	return nil
}

func (s *ChallengeStore) GetKeyAuth(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.tokens[token]
	return val, ok
}

func (s *ChallengeStore) SyncFromCluster(token, keyAuth string, deleted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if deleted {
		delete(s.tokens, token)
	} else {
		s.tokens[token] = keyAuth
	}
}
