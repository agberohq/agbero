// internal/security/token_test.go
package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

func TestGenerateNewKeyFile_Success(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.key")
	err := GenerateNewKeyFile(tmpFile)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	b, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "PRIVATE KEY") {
		t.Error("Invalid PEM format")
	}
}

func TestGenerateNewKeyFile_InvalidPath(t *testing.T) {
	err := GenerateNewKeyFile("/invalid/path/key")
	if err == nil {
		t.Error("Expected error on invalid path")
	}
}

func TestLoadKeys_Success(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.key")
	GenerateNewKeyFile(tmpFile)

	tm, err := LoadKeys(tmpFile)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if tm.privateKey == nil || tm.publicKey == nil {
		t.Error("Keys not loaded")
	}
}

func TestLoadKeys_InvalidPEM(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.key")
	os.WriteFile(tmpFile, []byte("invalid"), 0644)

	_, err := LoadKeys(tmpFile)
	if err == nil || !strings.Contains(err.Error(), "invalid pem") {
		t.Error("Expected PEM error")
	}
}

func TestLoadKeys_NotEd25519(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "rsa.key")
	// Mock RSA PEM (minimal)
	os.WriteFile(tmpFile, []byte(`-----BEGIN PRIVATE KEY-----
MIIBVAgBAQ==
-----END PRIVATE KEY-----`), 0644)

	_, err := LoadKeys(tmpFile)
	if err == nil || !strings.Contains(err.Error(), "not ed25519") {
		t.Error("Expected key type error")
	}
}

func TestMint_Success(t *testing.T) {
	tm := &TokenManager{} // Mock keys (real gen for test)
	_, priv, _ := ed25519.GenerateKey(nil)
	tm.privateKey = priv
	tm.publicKey = priv.Public().(ed25519.PublicKey)

	token, err := tm.Mint("service", 1*time.Hour)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if token == "" {
		t.Error("Empty token")
	}

	// Parse to verify claims
	parsed, _ := jwt.Parse(token, nil)
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "service" || claims["iss"] != "agbero" {
		t.Error("Invalid claims")
	}
}

func TestVerify_Success(t *testing.T) {
	tm := &TokenManager{} // Mock
	_, priv, _ := ed25519.GenerateKey(nil)
	tm.privateKey = priv
	tm.publicKey = priv.Public().(ed25519.PublicKey)

	token, _ := tm.Mint("service", 1*time.Hour)
	svc, err := tm.Verify(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if svc != "service" {
		t.Error("Invalid service name")
	}
}

func TestVerify_Expired(t *testing.T) {
	tm := &TokenManager{}
	_, priv, _ := ed25519.GenerateKey(nil)
	tm.privateKey = priv
	tm.publicKey = priv.Public().(ed25519.PublicKey)

	token, _ := tm.Mint("service", -1*time.Hour) // Expired
	_, err := tm.Verify(token)
	if err == nil || !strings.Contains(err.Error(), "expired") { // jwt.ErrTokenExpired
		t.Error("Expected expired error")
	}
}

func TestVerify_InvalidSig(t *testing.T) {
	tm := &TokenManager{}
	_, priv, _ := ed25519.GenerateKey(nil)
	tm.privateKey = priv
	tm.publicKey = priv.Public().(ed25519.PublicKey)

	token, _ := tm.Mint("service", 1*time.Hour)
	token = token + "invalid" // Corrupt

	_, err := tm.Verify(token)
	if err == nil {
		t.Error("Expected invalid sig error")
	}
}

func TestVerify_MissingSub(t *testing.T) {
	tm := &TokenManager{}
	_, priv, _ := ed25519.GenerateKey(nil)
	tm.privateKey = priv
	tm.publicKey = priv.Public().(ed25519.PublicKey)

	// Manual invalid token without sub
	claims := jwt.MapClaims{"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "iss": "agbero"}
	jwtt := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, _ := jwtt.SignedString(tm.privateKey)

	_, err := tm.Verify(token)
	if err == nil || !strings.Contains(err.Error(), "missing subject") {
		t.Error("Expected missing sub error")
	}
}
