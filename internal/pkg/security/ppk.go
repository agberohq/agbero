package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

type TokenClaims struct {
	Service string `json:"svc"`
	jwt.RegisteredClaims
}

// VerifiedToken holds the validated claims extracted from a service token.
// JTI is included so callers can check revocation lists without re-parsing the token.
type VerifiedToken struct {
	Service string
	JTI     string
	Expiry  time.Time
}

type PPK struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func PPKLoad(path string) (*PPK, error) {
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

	return &PPK{
		privateKey: edKey,
		publicKey:  edKey.Public().(ed25519.PublicKey),
	}, nil
}

func NewPPK(path string) error {
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

// Mint issues a signed service token with a random JTI for revocation support.
// The JTI is embedded in the token and returned as part of the signed string —
// callers retrieve it via Verify when they need to add it to a revocation list.
func (m *PPK) Mint(serviceName string, ttl time.Duration) (string, error) {
	p := NewPassword()
	jit, err := p.JTI()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := TokenClaims{
		Service: serviceName,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jit,
			Issuer:    woos.Name,
			Subject:   serviceName,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(m.privateKey)
}

// Verify validates a service token and returns the verified claims.
// The returned JTI can be used to check a revocation list before granting access.
func (m *PPK) Verify(tokenString string) (VerifiedToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return VerifiedToken{}, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		expiry := time.Time{}
		if claims.ExpiresAt != nil {
			expiry = claims.ExpiresAt.Time
		}
		return VerifiedToken{
			Service: claims.Service,
			JTI:     claims.ID,
			Expiry:  expiry,
		}, nil
	}

	return VerifiedToken{}, errors.New("invalid token claims")
}
