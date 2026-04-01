package tlsstore

import (
	"strings"
	"sync"

	"github.com/agberohq/keeper"
	"github.com/olekukonko/errors"
)

// KeeperStore implements Store using Keeper with proper namespacing
type KeeperStore struct {
	keeper *keeper.Keeper
	mu     sync.RWMutex
}

// NewKeeper creates a new Keeper-based certificate storage
func NewKeeper(k *keeper.Keeper) (*KeeperStore, error) {
	if k == nil {
		return nil, errors.New("keeper store is required")
	}

	// Initialize namespaces for different certificate sources.
	// These use LevelPasswordOnly so they auto-unlock with the master passphrase.
	// According to Keeper API, CreateBucket takes (scheme, namespace, level, createdBy)
	namespaces := []string{IssuerCustom, IssuerACME, IssuerLocal, IssuerCA, IssuerSystem}
	for _, ns := range namespaces {
		// Create bucket with LevelPasswordOnly - these unlock when master is unlocked
		// Using "certs" as the scheme, with sub-buckets for each issuer
		_ = k.CreateBucket("certs", ns, keeper.LevelPasswordOnly, "system")
	}

	return &KeeperStore{keeper: k}, nil
}

// Save stores certificate in the specified issuer's namespace
func (s *KeeperStore) Save(issuer, domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate issuer
	validIssuers := map[string]bool{
		IssuerCustom: true,
		IssuerACME:   true,
		IssuerLocal:  true,
		IssuerCA:     true,
		IssuerSystem: true,
	}
	if !validIssuers[issuer] {
		issuer = IssuerCustom
	}

	// Handle special case where a key might not have a corresponding cert (e.g., ACME Account Key)
	if len(certPEM) > 0 {
		if err := s.keeper.SetNamespacedFull("certs", issuer, domain+".crt", certPEM); err != nil {
			return err
		}
	}

	if len(keyPEM) > 0 {
		if err := s.keeper.SetNamespacedFull("certs", issuer, domain+".key", keyPEM); err != nil {
			return err
		}
	}

	return nil
}

// Load searches across namespaces in priority order to allow overrides
func (s *KeeperStore) Load(domain string) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Priority: custom (user-provided) > letsencrypt > local (dev)
	namespaces := []string{IssuerCustom, IssuerACME, IssuerLocal}

	for _, ns := range namespaces {
		cert, err1 := s.keeper.GetNamespacedFull("certs", ns, domain+".crt")
		key, err2 := s.keeper.GetNamespacedFull("certs", ns, domain+".key")

		if err1 == nil && err2 == nil {
			return cert, key, nil
		}
	}

	// Check CA and System namespaces as fallback for internal keys
	for _, ns := range []string{IssuerCA, IssuerSystem} {
		key, err := s.keeper.GetNamespacedFull("certs", ns, domain+".key")
		if err == nil {
			// Cert might be nil for system keys (like ACME account)
			cert, _ := s.keeper.GetNamespacedFull("certs", ns, domain+".crt")
			return cert, key, nil
		}
	}

	return nil, nil, ErrCertNotFound
}

// List aggregates domains from all certificate namespaces
func (s *KeeperStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domainMap := make(map[string]bool)
	namespaces := []string{IssuerCustom, IssuerACME, IssuerLocal}

	for _, ns := range namespaces {
		keys, err := s.keeper.ListPrefixNamespacedFull("certs", ns, "")
		if err != nil {
			// Bucket might not exist yet, that's fine
			continue
		}
		for _, key := range keys {
			if strings.HasSuffix(key, ".crt") {
				domain := strings.TrimSuffix(key, ".crt")
				// Convert back from safe name if needed
				domain = strings.ReplaceAll(domain, "_wildcard_", "*")
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

// Delete removes certificate from all namespaces to ensure complete cleanup
func (s *KeeperStore) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete from all possible namespaces
	namespaces := []string{IssuerCustom, IssuerACME, IssuerLocal, IssuerCA, IssuerSystem}
	for _, ns := range namespaces {
		// Convert domain to safe name for storage
		safeDomain := strings.ReplaceAll(domain, "*", "_wildcard_")
		_ = s.keeper.DeleteNamespacedFull("certs", ns, safeDomain+".crt")
		_ = s.keeper.DeleteNamespacedFull("certs", ns, safeDomain+".key")
	}
	return nil
}
