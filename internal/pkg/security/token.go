package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

type TokenClaims struct {
	Service string `json:"svc"`
	jwt.RegisteredClaims
}

type Manager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func LoadKeys(path string) (*Manager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid pem file: missing PRIVATE KEY block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ed25519")
	}

	return &Manager{
		privateKey: edKey,
		publicKey:  edKey.Public().(ed25519.PublicKey),
	}, nil
}

func GenerateNewKeyFile(path string) error {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return err
	}

	return f.Chmod(0600)
}

func (m *Manager) Mint(serviceName string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		Service: serviceName,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "agbero-api",
			Subject:   serviceName,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(m.privateKey)
}

func (m *Manager) Verify(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims.Service, nil
	}

	return "", errors.New("invalid token claims")
}
