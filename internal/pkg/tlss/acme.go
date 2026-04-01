package tlss

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/tlss/tlsstore"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/olekukonko/ll"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string                        { return u.Email }
func (u *AcmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type ACMEProvider struct {
	logger     *ll.Logger
	storage    tlsstore.Store
	challenges *ChallengeStore
	user       *AcmeUser
	mu         sync.Mutex
	// glocal     alaye.LetsEncrypt
}

func NewACMEProvider(logger *ll.Logger, storage tlsstore.Store, challenges *ChallengeStore, global alaye.LetsEncrypt) *ACMEProvider {
	return &ACMEProvider{
		logger:     logger,
		storage:    storage,
		challenges: challenges,
	}
}

func (p *ACMEProvider) ObtainCert(domain string, setting alaye.LetsEncrypt) (*tls.Certificate, []byte, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := setting.Validate(); err != nil {
		p.logger.Errorf("invalid Let's Encrypt setting: %s", err)
		return nil, nil, nil, err
	}

	client, err := p.setupLegoClient(setting)
	if err != nil {
		return nil, nil, nil, err
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acme: obtain error: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certs.Certificate, certs.PrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	_ = p.storage.Save(tlsstore.IssuerACME, domain, certs.Certificate, certs.PrivateKey)
	return &tlsCert, certs.Certificate, certs.PrivateKey, nil
}

func (p *ACMEProvider) setupLegoClient(setting alaye.LetsEncrypt) (*lego.Client, error) {
	if p.user == nil {
		if err := p.loadUser(setting); err != nil {
			return nil, err
		}
	}

	config := lego.NewConfig(p.user)
	if setting.Pebble.Enabled.Active() {
		p.logger.Warn("pebble is enabled, this is not recommended for production")
		config.CADirURL = setting.Pebble.URL
		if config.CADirURL == "" {
			config.CADirURL = "https://localhost:14000/dir"
		}
		if setting.Pebble.Insecure.Active() {
			config.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	} else {
		if setting.Staging.Active() {
			config.CADirURL = woos.LetsEncryptStagingDir
			p.logger.Warn("staging Let's Encrypt is enabled, this is not recommended for production")
		} else {
			config.CADirURL = woos.LetsEncryptProdDir
		}
	}

	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	err = client.Challenge.SetHTTP01Provider(p.challenges)
	if err != nil {
		return nil, err
	}

	if p.user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			reg, err = client.Registration.ResolveAccountByKey()
			if err != nil {
				return nil, err
			}
		}
		p.user.Registration = reg
	}

	return client, nil
}

func (p *ACMEProvider) loadUser(setting alaye.LetsEncrypt) error {
	if setting.Email == "" {
		return fmt.Errorf("email is required for Let's Encrypt")
	}
	var privateKey crypto.PrivateKey

	// Load exclusively from store
	_, keyBytes, keyErr := p.storage.Load("acme_account")
	if keyErr == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			var err error
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					p.logger.Warn("failed to parse existing account key, generating new one")
				}
			}
		}
	}
	if privateKey == nil {
		var err error
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		bytes, _ := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		_ = p.storage.Save(tlsstore.IssuerSystem, "acme_account", nil, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}))
	}
	p.user = &AcmeUser{
		Email: setting.Email,
		key:   privateKey,
	}
	return nil
}
