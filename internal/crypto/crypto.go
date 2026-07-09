// Package crypto encapsula a cifragem de URLs com AES-256-CTR.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeySize é o tamanho exigido da chave, em bytes (AES-256).
const KeySize = 32

var ErrCipherTextTooShort = errors.New("cipher text is too short")

// Cipher cifra e decifra strings usando AES-CTR com IV aleatório.
type Cipher struct {
	key []byte
}

func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes long, got %d", KeySize, len(key))
	}
	return &Cipher{key: key}, nil
}

func (c *Cipher) Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	data := []byte(plainText)
	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]

	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return hex.EncodeToString(cipherText), nil
}

func (c *Cipher) Decrypt(encrypted string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	cipherText, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", ErrCipherTextTooShort
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
