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

// TokenSize é o tamanho, em bytes, do token de gerenciamento (64 hex chars).
const TokenSize = 32

// GenerateToken gera um token secreto de 32 bytes aleatórios, hex-encoded
// (64 caracteres). Devolvido ao criador do link uma única vez.
func GenerateToken() (string, error) {
	b := make([]byte, TokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// TokenSHA256 devolve o SHA-256 hex (64 chars) de um token. Apenas o hash é
// persistido; o token em claro nunca é gravado. SHA-256 (não HMAC) porque o
// token já é aleatório de alta entropia — não precisa de chave secreta.
func TokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
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
