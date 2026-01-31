package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

type TokenManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func LoadKeys(privateKeyPath string) (*TokenManager, error) {
	b, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, errors.Newf("read key file: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != woos.BlockPrivateKey {
		return nil, woos.ErrInvalidPEMFile
	}

	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Newf("parse private key: %w", err)
	}

	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, woos.ErrNotEd25519Key
	}

	return &TokenManager{
		privateKey: priv,
		publicKey:  priv.Public().(ed25519.PublicKey),
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
		Type:  woos.BlockPrivateKey,
		Bytes: b,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, pemBlock)
}

func (tm *TokenManager) Mint(serviceName string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub": serviceName,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(ttl).Unix(),
		"iss": woos.DefaultIssuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(tm.privateKey)
}

func (tm *TokenManager) Verify(tokenString string) (serviceName string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("%w: %v", woos.ErrUnexpectedSiningMethod, token.Header[woos.TokenAlg])
		}
		return tm.publicKey, nil
	})

	if err != nil {
		return "", errors.Newf("parse err: %w", err)
	}

	if !token.Valid {
		return "", woos.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", woos.ErrInvalidClaims
	}

	sub, ok := claims[woos.TokenSub].(string)
	if !ok || sub == "" {
		return "", woos.ErrMissingTokenSubject
	}

	return sub, nil
}
