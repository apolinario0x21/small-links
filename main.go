package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	urlStore    = make(map[string]string)
	mu          sync.Mutex
	secretKey   = []byte("secretaeskey12345678901234567890")
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func encrypt(originalUrl string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	plainText := []byte(originalUrl)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(cipherText)
}

func decrypt(encryptedUrl string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := hex.DecodeString(encryptedUrl)
	if err != nil {
		log.Fatal(err)
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func generateShortId() string {
	b := make([]rune, 6)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(lettersRune))))
		if err != nil {
			log.Fatal(err)
		}
		b[i] = lettersRune[num.Int64()]
	}
	return string(b)
}

func shortenHandler(c *gin.Context) {
	originalUrl := c.Query("url")

	if originalUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is missing"})
		return
	}

	if !(strings.HasPrefix(originalUrl, "https://") || strings.HasPrefix(originalUrl, "http://")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL must start with http:// or https://"})
		return
	}

	encryptedURL := encrypt(originalUrl)
	shortId := generateShortId()

	mu.Lock()
	urlStore[shortId] = encryptedURL
	mu.Unlock()

	host := c.Request.Host
	scheme := "https"
	shortUrl := scheme + "://" + host + "/" + shortId

	c.JSON(http.StatusOK, gin.H{
		"original_url": originalUrl,
		"short_url":    shortUrl,
	})
}

func redirectHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	mu.Lock()
	encryptedUrl, ok := urlStore[shortId]
	mu.Unlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
		return
	}

	decrypted := decrypt(encryptedUrl)
	c.Redirect(http.StatusFound, decrypted)
}

func main() {
	router := gin.Default()
	router.GET("/shorten", shortenHandler)
	router.GET("/:shortId", redirectHandler)

	router.Run(":8080")
}
