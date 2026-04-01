package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

const (
	pemTypePrivateKey = "PRIVATE KEY"
)

type TokenClaims struct {
	Service string `json:"svc"`
	jwt.RegisteredClaims
}

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
	if block == nil || block.Type != pemTypePrivateKey {
		return nil, errors.New("invalid PEM: missing PRIVATE KEY block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}

	return &PPK{
		privateKey: edKey,
		publicKey:  edKey.Public().(ed25519.PublicKey),
	}, nil
}

func NewPPK(path string) error {
	_, pemBytes, err := GeneratePPK()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(pemBytes)
	return err
}

func (m *PPK) Mint(service string, ttl time.Duration) (string, error) {
	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := TokenClaims{
		Service: service,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    woos.Issuer,
			Subject:   service,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(m.privateKey)
}

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

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return VerifiedToken{}, errors.New("invalid token claims")
	}

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

func GeneratePPK() (*PPK, []byte, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	pemBlock := &pem.Block{Type: pemTypePrivateKey, Bytes: b}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, pemBlock); err != nil {
		return nil, nil, err
	}

	return &PPK{
		privateKey: priv,
		publicKey:  priv.Public().(ed25519.PublicKey),
	}, buf.Bytes(), nil
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
