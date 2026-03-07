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
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string                        { return u.Email }
func (u *AcmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type ClusterProvider struct {
	store *ChallengeStore
}

func (c *ClusterProvider) Present(domain, token, keyAuth string) error {
	return c.store.Present(domain, token, keyAuth)
}

func (c *ClusterProvider) CleanUp(domain, token, keyAuth string) error {
	return c.store.CleanUp(domain, token, keyAuth)
}

func (m *Manager) setupLegoClient() (*lego.Client, error) {
	email := m.global.LetsEncrypt.Email
	if email == "" {
		return nil, fmt.Errorf("email is required for Let's Encrypt")
	}

	userKey, err := m.loadOrGenAccountKey()
	if err != nil {
		return nil, err
	}

	user := &AcmeUser{
		Email: email,
		key:   userKey,
	}

	config := lego.NewConfig(user)

	if m.global.LetsEncrypt.Pebble.Enabled {
		config.CADirURL = m.global.LetsEncrypt.Pebble.URL
		if config.CADirURL == "" {
			config.CADirURL = "https://localhost:14000/dir"
		}
		if m.global.LetsEncrypt.Pebble.Insecure {
			config.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	} else if m.global.LetsEncrypt.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		m.logger.Fields("email", email).Debug("acme registration (existing or new)")
	}
	user.Registration = reg

	provider := &ClusterProvider{store: m.Challenges}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, err
	}

	return client, nil
}

func (m *Manager) loadOrGenAccountKey() (crypto.PrivateKey, error) {
	path := filepath.Join(m.global.Storage.CertsDir, "acme_account.key")

	if _, err := os.Stat(path); err == nil {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("no PEM data found in account key")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	bytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return nil, err
	}

	return privateKey, nil
}
