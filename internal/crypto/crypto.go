// Package crypto encapsula a cifragem de URLs com AES-256-GCM.
//
// Registros gravados antes da migração para GCM usavam AES-CTR sem
// autenticação; Decrypt tenta GCM primeiro e cai para o formato CTR
// legado quando a autenticação falha.
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

// Cipher cifra com AES-GCM (nonce aleatório prefixado ao ciphertext) e
// decifra tanto GCM quanto o formato CTR legado.
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

	if plainText, err := c.decryptGCM(cipherText); err == nil {
		return plainText, nil
	}

	return c.decryptLegacyCTR(cipherText)
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

// decryptLegacyCTR decifra o formato antigo (AES-CTR, IV de 16 bytes
// prefixado, sem autenticação). Apenas leitura; nada novo é gravado assim.
func (c *Cipher) decryptLegacyCTR(cipherText []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", ErrCipherTextTooShort
	}

	iv := cipherText[:aes.BlockSize]
	data := make([]byte, len(cipherText)-aes.BlockSize)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, cipherText[aes.BlockSize:])

	return string(data), nil
}
