package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type URLData struct {
	ID          int       `db:"id"`
	ShortID     string    `db:"short_id"`
	OriginalURL string    `db:"original_url"`
	CreatedAt   time.Time `db:"created_at"`
	AccessCount int       `db:"access_count"`
}

var (
	db          *sql.DB
	mu          sync.RWMutex
	secretKey   []byte
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func init() {

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		log.Fatal("ENCRYPTION_KEY environment variable is not set")
	}

	if len(key) != 32 {
		log.Fatal("Encryption key must be 32 bytes long")
	}

	secretKey = []byte(key)

	connectDB()
	migrateDB()
}

func connectDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open a DB connection: ", err)
	}

	for i := 0; i < 5; i++ {
		err = db.Ping()
		if err == nil {
			log.Println("Successfully connected to the database!")
			return
		}
		log.Printf("Unsuccessful database connection, retrying in 5 seconds... (%d/5)", i+1)
		time.Sleep(5 * time.Second)
	}
	log.Fatal("Several unsuccessful connection attempts: ", err)
}

func migrateDB() {
	const createTableSQL = `
	CREATE TABLE IF NOT EXISTS urls (
		id SERIAL PRIMARY KEY,
		short_id VARCHAR(6) UNIQUE NOT NULL,
		original_url TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL,
		access_count INT NOT NULL DEFAULT 0
	);`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Fatal("Failed to create 'urls' table: ", err)
	}

	log.Println("Database migration completed.")
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

		var exists bool
		query := "SELECT EXISTS(SELECT 1 FROM urls WHERE short_id = $1)"
		err := db.QueryRow(query, shortId).Scan(&exists)
		if err != nil {
			log.Printf("Database check error: %v", err)
			continue
		}

		if !exists {
			return shortId
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
		ShortID:     shortId,
		OriginalURL: encryptedURL,
		CreatedAt:   time.Now(),
		AccessCount: 0,
	}

	insertSQL := `INSERT INTO urls (short_id, original_url, created_at, access_count) VALUES ($1, $2, $3, $4)`
	_, err := db.Exec(insertSQL, urlData.ShortID, urlData.OriginalURL, urlData.CreatedAt, urlData.AccessCount)
	if err != nil {
		log.Printf("Failed to insert URL into DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
		return
	}

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

	var urlData URLData
	row := db.QueryRow(`SELECT short_id, original_url, access_count FROM urls WHERE short_id = $1`, shortId)
	err := row.Scan(&urlData.ShortID, &urlData.OriginalURL, &urlData.AccessCount)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		log.Printf("Failed to query DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	updateSQL := `UPDATE urls SET access_count = access_count + 1 WHERE short_id = $1`
	_, err = db.Exec(updateSQL, shortId)
	if err != nil {
		log.Printf("Failed to update access count: %v", err)
	}

	decrypted := decrypt(urlData.OriginalURL)
	if decrypted == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt URL"})
		return
	}

	c.Redirect(http.StatusFound, decrypted)
}

func statsHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	var urlData URLData
	row := db.QueryRow(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = $1`, shortId)
	err := row.Scan(&urlData.ShortID, &urlData.OriginalURL, &urlData.CreatedAt, &urlData.AccessCount)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		log.Printf("Failed to query DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
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
	var totalUrls int
	err := db.QueryRow(`SELECT COUNT(*) FROM urls`).Scan(&totalUrls)
	if err != nil {
		log.Printf("Failed to query total URLs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "unhealthy",
			"error":  "Failed to get total URL count",
		})
		return
	}

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
