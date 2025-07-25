package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type URLData struct {
	OriginalURL string    `json:"original_url"`
	CreatedAt   time.Time `json:"created_at"`
	AccessCount int       `json:"access_count"`
}

var (
	urlStore    = make(map[string]URLData)
	mu          sync.RWMutex
	secretKey   []byte
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	dataFile    = "urls.json"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables directly.")
	}

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		log.Fatal("ENCRYPTION_KEY environment variable is not set")
	}

	if len(key) != 32 {
		log.Fatal("Encryption key must be 32 bytes long")
	}

	secretKey = []byte(key)
	loadData()
}

func loadData() {
	file, err := os.Open(dataFile)
	if err != nil {
		log.Println("No existing data file found, starting fresh.")
		return
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&urlStore); err != nil {
		log.Printf("Error decoding data %v:", err)
	} else {
		log.Printf("Loaded %d URLs from data file.", len(urlStore))
	}
}

func saveData() {
	mu.RLock()
	defer mu.RUnlock()

	file, err := os.Create(dataFile)
	if err != nil {
		log.Printf("Error creating data file: %v", err)
		return
	}

	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(urlStore); err != nil {
		log.Printf("Error saving data: %v", err)
	}
}

func encrypt(originalUrl string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		return ""
	}

	plainText := []byte(originalUrl)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := rand.Read(iv); err != nil {
		log.Printf("IV generation error: %v", err)
		return ""
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(cipherText)
}

func decrypt(encryptedUrl string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		return ""
	}

	cipherText, err := hex.DecodeString(encryptedUrl)
	if err != nil {
		log.Printf("Hex decode error: %v", err)
		return ""
	}

	if len(cipherText) < aes.BlockSize {
		log.Printf("Cipher text is too short")
		return ""
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func generateShortId() string {
	for {
		b := make([]rune, 6)
		for i := range b {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(lettersRune))))
			if err != nil {
				log.Printf("Random number generation error: %v", err)
				continue
			}

			b[i] = lettersRune[num.Int64()]
		}

		shortId := string(b)

		mu.RLock()
		_, exists := urlStore[shortId]
		mu.RUnlock()

		if !exists {
			return string(b)
		}
	}
}

func getScheme(c *gin.Context) string {
	if c.GetHeader("X-Forwarded-Proto") == "https" {
		return "https"
	}

	if c.GetHeader("X-Forwarded-Ssl") == "on" {
		return "https"
	}

	if c.Request.TLS != nil {
		return "https"
	}

	return "http"
}

func isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func shortenHandler(c *gin.Context) {
	originalUrl := c.Query("url")

	if originalUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is missing"})
		return
	}

	if !isValidURL(originalUrl) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL must start with http:// or https://"})
		return
	}

	encryptedURL := encrypt(originalUrl)
	if encryptedURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt URL"})
		return
	}

	shortId := generateShortId()

	urlData := URLData{
		OriginalURL: encryptedURL,
		CreatedAt:   time.Now(),
		AccessCount: 0,
	}

	mu.Lock()
	urlStore[shortId] = urlData
	mu.Unlock()

	go saveData()

	scheme := getScheme(c)
	host := c.Request.Host
	shortUrl := scheme + "://" + host + "/" + shortId

	c.JSON(http.StatusOK, gin.H{
		"original_url": originalUrl,
		"short_url":    shortUrl,
		"created_at":   urlData.CreatedAt,
	})
}

func redirectHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	mu.Lock()
	urlData, ok := urlStore[shortId]
	if ok {
		urlData.AccessCount++
		urlStore[shortId] = urlData
	}

	mu.Unlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
		return
	}

	decrypted := decrypt(urlData.OriginalURL)
	if decrypted == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt URL"})
		return
	}

	go saveData()
	c.Redirect(http.StatusFound, decrypted)
}

func statsHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	mu.RLock()
	urlData, ok := urlStore[shortId]
	mu.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
		return
	}

	decrypted := decrypt(urlData.OriginalURL)
	if decrypted == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt URL"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"short_id":     shortId,
		"original_url": decrypted,
		"created_at":   urlData.CreatedAt,
		"access_count": urlData.AccessCount,
	})
}

func healthHandler(c *gin.Context) {
	mu.RLock()
	totalUrls := len(urlStore)
	mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"total_urls": totalUrls,
		"timestamp":  time.Now(),
	})
}

func main() {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	router.GET("/health", healthHandler)
	router.GET("/shorten", shortenHandler)
	router.GET("/stats/:shortId", statsHandler)
	router.GET("/:shortId", redirectHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("No PORT environment variable set, defaulting to %s", port)
	}

	log.Printf("Starting server on port %s", port)
	router.Run(":" + port)
}
