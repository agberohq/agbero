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
	config     *alaye.LetsEncrypt
	storage    Store
	challenges *ChallengeStore
	user       *AcmeUser
	mu         sync.Mutex
}

func NewACMEProvider(logger *ll.Logger, config *alaye.LetsEncrypt, storage Store, challenges *ChallengeStore) *ACMEProvider {
	return &ACMEProvider{
		logger:     logger,
		config:     config,
		storage:    storage,
		challenges: challenges,
	}
}

func (p *ACMEProvider) ObtainCert(domain string) (*tls.Certificate, []byte, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, err := p.setupLegoClient()
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

	return &tlsCert, certs.Certificate, certs.PrivateKey, nil
}

func (p *ACMEProvider) setupLegoClient() (*lego.Client, error) {
	if p.user == nil {
		if err := p.loadUser(); err != nil {
			return nil, err
		}
	}

	config := lego.NewConfig(p.user)

	if p.config.Pebble.Enabled {
		config.CADirURL = p.config.Pebble.URL
		if config.CADirURL == "" {
			config.CADirURL = "https://localhost:14000/dir"
		}
		if p.config.Pebble.Insecure {
			config.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	} else if p.config.Staging {
		config.CADirURL = woos.LetsEncryptStagingDir
	} else {
		config.CADirURL = woos.LetsEncryptProdDir
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

func (p *ACMEProvider) loadUser() error {
	email := p.config.Email
	if email == "" {
		return fmt.Errorf("email is required for Let's Encrypt")
	}
	var privateKey crypto.PrivateKey
	_, keyBytes, keyErr := p.storage.Load("acme_account")
	if keyErr == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			var err error
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				// Try RSA if EC fails (legacy keys)
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
		_ = p.storage.Save("acme_account", nil, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}))
	}
	p.user = &AcmeUser{
		Email: email,
		key:   privateKey,
	}
	return nil
}
