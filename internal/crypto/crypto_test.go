package crypto

import (
	"errors"
	"testing"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestNewRejectsWrongKeySize(t *testing.T) {
	if _, err := New([]byte("curta")); err == nil {
		t.Error("New should reject a key shorter than 32 bytes")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	original := "https://www.example.com/caminho?q=1"
	encrypted, err := c.Encrypt(original)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == original {
		t.Error("Encrypt should not return the plain text")
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != original {
		t.Errorf("round trip = %q, want %q", decrypted, original)
	}
}

func TestEncryptUsesRandomIV(t *testing.T) {
	c, _ := New(testKey)
	a, _ := c.Encrypt("https://www.example.com")
	b, _ := c.Encrypt("https://www.example.com")
	if a == b {
		t.Error("two encryptions of the same input should differ (random IV)")
	}
}

func TestDecryptRejectsShortCipherText(t *testing.T) {
	c, _ := New(testKey)
	if _, err := c.Decrypt("abcd"); !errors.Is(err, ErrCipherTextTooShort) {
		t.Errorf("err = %v, want ErrCipherTextTooShort", err)
	}
}

func TestDecryptRejectsInvalidHex(t *testing.T) {
	c, _ := New(testKey)
	if _, err := c.Decrypt("zz-not-hex"); err == nil {
		t.Error("Decrypt should reject invalid hex input")
	}
}
