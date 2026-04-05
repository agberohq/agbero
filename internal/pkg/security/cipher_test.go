package security

import (
	"bytes"
	"testing"
)

func TestEncryptionCycle(t *testing.T) {
	secret := "super-secret-cluster-key-12345"
	c, err := NewCipher(secret)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	original := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD\n-----END PRIVATE KEY-----")

	encrypted, err := c.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(original, encrypted) {
		t.Fatal("Ciphertext should not match plaintext")
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatal("Decrypted content does not match original")
	}
}

func TestDecryptBadKey(t *testing.T) {
	c1, _ := NewCipher("key-one")
	c2, _ := NewCipher("key-two")

	data := []byte("secret-data")
	encrypted, _ := c1.Encrypt(data)

	_, err := c2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("Expected decryption failure with wrong key, got nil")
	}
}

func TestDecryptCorruptData(t *testing.T) {
	c, _ := NewCipher("key")
	data := []byte("secret")
	encrypted, _ := c.Encrypt(data)

	// Corrupt last byte
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := c.Decrypt(encrypted)
	if err == nil {
		t.Fatal("Expected error for corrupt data")
	}
}
