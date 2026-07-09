package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

var (
	db          *sql.DB
	repo        storage.Repository
	secretKey   []byte
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func bootstrap() config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	secretKey = []byte(cfg.EncryptionKey)

	db, err = storage.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Successfully connected to the database!")

	if err := storage.Migrate(db); err != nil {
		log.Fatal(err)
	}
	log.Println("Database migration completed.")

	repo = storage.NewPostgres(db)

	return cfg
}

func encrypt(originalUrl string) string {
	c, err := crypto.New(secretKey)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		return ""
	}

	encrypted, err := c.Encrypt(originalUrl)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		return ""
	}

	return encrypted
}

func decrypt(encryptedUrl string) string {
	c, err := crypto.New(secretKey)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		return ""
	}

	decrypted, err := c.Decrypt(encryptedUrl)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		return ""
	}

	return decrypted
}

func generateShortId(ctx context.Context) string {
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

		exists, err := repo.ShortIDExists(ctx, shortId)
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

	shortId := generateShortId(c.Request.Context())
	urlData := storage.URLData{
		ShortID:     shortId,
		OriginalURL: encryptedURL,
		CreatedAt:   time.Now(),
		AccessCount: 0,
	}

	err := repo.Insert(c.Request.Context(), urlData)
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

	urlData, err := repo.FindForRedirect(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		log.Printf("Failed to query DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if err := repo.IncrementAccessCount(c.Request.Context(), shortId); err != nil {
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

	urlData, err := repo.FindByShortID(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
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
	totalUrls, err := repo.CountURLs(c.Request.Context())
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

func setupRouter() *gin.Engine {
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

	return router
}

func main() {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	cfg := bootstrap()

	router := setupRouter()

	log.Printf("Starting server on port %s", cfg.Port)
	router.Run(":" + cfg.Port)
}
