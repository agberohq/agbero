package tlsstore

import (
	"sync"
)

type certBundle struct {
	certPEM []byte
	keyPEM  []byte
}

// MemoryStore implements Store using in-memory storage (ephemeral mode)
type MemoryStore struct {
	mu    sync.RWMutex
	certs map[string]map[string]certBundle // issuer -> domain -> bundle
}

// NewMemory creates a new in-memory certificate storage
func NewMemory() *MemoryStore {
	m := &MemoryStore{
		certs: make(map[string]map[string]certBundle),
	}
	// Initialize the issuer maps
	for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal, IssuerCA, IssuerSystem} {
		m.certs[issuer] = make(map[string]certBundle)
	}
	return m
}

// Save stores certificate and key in memory under the specific issuer
func (s *MemoryStore) Save(issuer, domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.certs[issuer] == nil {
		s.certs[issuer] = make(map[string]certBundle)
	}

	s.certs[issuer][domain] = certBundle{
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
	return nil
}

// Load retrieves certificate and key from memory using priority resolution
func (s *MemoryStore) Load(domain string) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Priority: custom (user-provided) > letsencrypt > local (dev)
	for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal, IssuerCA, IssuerSystem} {
		if issuerMap, ok := s.certs[issuer]; ok {
			if bundle, found := issuerMap[domain]; found {
				return bundle.certPEM, bundle.keyPEM, nil
			}
		}
	}

	return nil, nil, ErrCertNotFound
}

// List returns all domains with stored certificates across all issuers
func (s *MemoryStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domainMap := make(map[string]bool)
	for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal} {
		if issuerMap, ok := s.certs[issuer]; ok {
			for domain := range issuerMap {
				domainMap[domain] = true
			}
		}
	}

	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}
	return domains, nil
}

// Delete removes certificate from memory across ALL issuers
func (s *MemoryStore) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, issuerMap := range s.certs {
		delete(issuerMap, domain)
	}
	return nil
}
