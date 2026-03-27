package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Password handles password and hash generation
type Password struct{}

// NewPassword creates a new password generator
func NewPassword() *Password {
	return &Password{}
}

// Generate creates a cryptographically secure random password
// of the specified length (default 32 if length <= 0)
func (g *Password) Generate(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random generation failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

// Hash generates a bcrypt hash from a plaintext password
func (g *Password) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// HashWithCost generates a bcrypt hash with custom cost
func (g *Password) HashWithCost(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// Make creates a random password and returns both the plaintext and its hash
func (g *Password) Make(length int) (password, hash string, err error) {
	password, err = g.Generate(length)
	if err != nil {
		return "", "", err
	}
	hash, err = g.Hash(password)
	if err != nil {
		return "", "", err
	}
	return password, hash, nil
}

// Verify compares a plaintext password against a bcrypt hash
func (g *Password) Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Dummy returns a dummy bcrypt hash for timing attack resistance
func (g *Password) Dummy() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	return hash
}

// It returns the JTI string or an error if random generation fails.
func (g *Password) JTI() (string, error) {
	jtiBytes, err := g.Random(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(jtiBytes), nil
}

func (g *Password) Random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}
	return b, err
}
