package security

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/olekukonko/errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrDecrypt = errors.New("decryption failed")

// Cipher handles authenticated encryption using XChaCha20-Poly1305.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a cipher.
// It attempts to decode secret as Base64.
// If decoding fails or length != 32, it hashes the string to generate a 32-byte key.
func NewCipher(secret string) (*Cipher, error) {
	if secret == "" {
		return nil, errors.New("secret cannot be empty")
	}

	var key []byte
	var err error

	key, err = base64.StdEncoding.DecodeString(secret)

	if err != nil || len(key) != chacha20poly1305.KeySize {
		h := sha256.Sum256([]byte(secret))
		key = h[:]
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &Cipher{aead: aead}, nil
}

func NewCipherFromKey(key []byte) (*Cipher, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("cipher not initialized")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("cipher not initialized")
	}
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecrypt
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
