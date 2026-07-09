// Package crypto encapsula a cifragem de URLs com AES-256-GCM e o
// HMAC-SHA256 usado para dedup por lookup determinístico.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeySize é o tamanho exigido da chave, em bytes (AES-256).
const KeySize = 32

var ErrCipherTextTooShort = errors.New("cipher text is too short")

// Cipher cifra e decifra com AES-GCM autenticado, nonce aleatório
// prefixado ao ciphertext.
type Cipher struct {
	key []byte
}

func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes long, got %d", KeySize, len(key))
	}
	return &Cipher{key: key}, nil
}

// Hash retorna o HMAC-SHA256 da URL, hex-encoded (64 caracteres).
// Determinístico: permite localizar uma URL já encurtada sem decifrar
// os registros, já que a cifragem com nonce aleatório impede busca
// direta pelo ciphertext.
func (c *Cipher) Hash(url string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(url))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Cipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *Cipher) Encrypt(plainText string) (string, error) {
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(sealed), nil
}

func (c *Cipher) Decrypt(encrypted string) (string, error) {
	cipherText, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	return c.decryptGCM(cipherText)
}

func (c *Cipher) decryptGCM(cipherText []byte) (string, error) {
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", ErrCipherTextTooShort
	}

	plainText, err := gcm.Open(nil, cipherText[:nonceSize], cipherText[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
