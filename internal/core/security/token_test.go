package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// Generate a valid RSA key so ParsePKCS8PrivateKey succeeds
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal to PKCS8
	b, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	// Write to PEM
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
	f.Close()

	// Now LoadKeys should succeed parsing but fail type assertion
	_, err = LoadKeys(tmpFile)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "key is not ed25519") {
		t.Errorf("Expected 'key is not ed25519' error, got: %v", err)
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

	// Parse to verify claims (skipping sig check just to read claims)
	parsed, _, _ := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if parsed == nil {
		t.Fatal("Failed to parse token")
	}
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
