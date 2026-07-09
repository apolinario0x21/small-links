package crypto

import (
	"encoding/hex"
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

func TestHashIsDeterministicAndDistinct(t *testing.T) {
	c, _ := New(testKey)

	a := c.Hash("https://www.example.com")
	b := c.Hash("https://www.example.com")
	other := c.Hash("https://www.example.org")

	if a != b {
		t.Error("Hash must be deterministic for the same URL")
	}
	if a == other {
		t.Error("Hash must differ for different URLs")
	}
	if len(a) != 64 {
		t.Errorf("Hash length = %d, want 64 hex chars", len(a))
	}
}

func TestHashDependsOnKey(t *testing.T) {
	c1, _ := New(testKey)
	c2, _ := New([]byte("ffffffffffffffffffffffffffffffff"))

	if c1.Hash("https://www.example.com") == c2.Hash("https://www.example.com") {
		t.Error("Hash must depend on the key (HMAC)")
	}
}

func TestDecryptTamperedGCMFailsAuthentication(t *testing.T) {
	c, _ := New(testKey)
	encrypted, _ := c.Encrypt("https://www.example.com")

	raw, _ := hex.DecodeString(encrypted)
	raw[len(raw)-1] ^= 0xff
	tampered := hex.EncodeToString(raw)

	if _, err := c.Decrypt(tampered); err == nil {
		t.Error("tampered cipher text must fail GCM authentication")
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
