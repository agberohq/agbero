package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/config"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/caddyserver/certmagic"
	"github.com/olekukonko/errors"
)

const (
	letsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Let's Encrypt 6-day profile name (ACME profile)
	acmeProfileShortLived = "shortlived"
)

type tlsManager struct {
	logger      anyLogger
	hostManager *discovery.Host
	global      *config.GlobalConfig
	cmMu        sync.Mutex
	cmCfg       *certmagic.Config

	// cache local certs by "certPath|keyPath"
	localMu    sync.RWMutex
	localCache map[string]*tls.Certificate
}

func (m *tlsManager) ensureCertMagic(next http.Handler) (*certmagic.ACMEIssuer, http.Handler, error) {
	m.cmMu.Lock()
	defer m.cmMu.Unlock()

	if m.cmCfg != nil {
		iss := m.firstACMEIssuer(m.cmCfg)
		if iss == nil {
			return nil, next, errors.New("certmagic configured without ACME issuer")
		}
		return iss, iss.HTTPChallengeHandler(next), nil
	}

	email := strings.TrimSpace(m.global.LEEmail)
	if email == "" {
		return nil, next, errors.New("le_email is empty")
	}

	cmCfg := certmagic.NewDefault()

	// Gate on-demand issuance to only configured hosts.
	cmCfg.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			_ = ctx // currently unused, but kept for API compatibility

			name = normalizeSubject(name)
			if m.hostManager.Get(name) != nil {
				return nil
			}
			return errors.Newf("on-demand denied for %q", name)
		},
	}

	acme := certmagic.ACMEIssuer{
		Email:  email,
		Agreed: true,
	}

	if m.global.Development {
		acme.CA = letsEncryptStagingDir
	} else {
		acme.CA = letsEncryptProdDir
	}

	// Optional: enable short-lived later
	// acme.Profile = acmeProfileShortLived

	issuer := certmagic.NewACMEIssuer(cmCfg, acme)
	cmCfg.Issuers = []certmagic.Issuer{issuer}

	m.cmCfg = cmCfg
	return issuer, issuer.HTTPChallengeHandler(next), nil
}

func (m *tlsManager) firstACMEIssuer(cm *certmagic.Config) *certmagic.ACMEIssuer {
	for _, iss := range cm.Issuers {
		if a, ok := iss.(*certmagic.ACMEIssuer); ok {
			return a
		}
	}
	return nil
}

func (m *tlsManager) getLocalCertificate(local config.LocalCert, host string) (*tls.Certificate, error) {
	certFile := strings.TrimSpace(local.CertFile)
	keyFile := strings.TrimSpace(local.KeyFile)

	if certFile == "" || keyFile == "" {
		return nil, errors.Newf("local tls requires cert_file and key_file (host=%q)", host)
	}

	certFile = filepath.Clean(certFile)
	keyFile = filepath.Clean(keyFile)
	cacheKey := certFile + "|" + keyFile

	m.localMu.RLock()
	if c := m.localCache[cacheKey]; c != nil {
		m.localMu.RUnlock()
		return c, nil
	}
	m.localMu.RUnlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.Newf("load local cert (host=%q): %w", host, err)
	}

	m.localMu.Lock()
	m.localCache[cacheKey] = &cert
	m.localMu.Unlock()

	return &cert, nil
}
