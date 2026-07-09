// Package http contém os handlers, middleware e rotas da API.
package http

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

var lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// Server agrega as dependências dos handlers.
type Server struct {
	repo   storage.Repository
	cipher *crypto.Cipher
}

func New(repo storage.Repository, cipher *crypto.Cipher) *Server {
	return &Server{repo: repo, cipher: cipher}
}

func (s *Server) Router() *gin.Engine {
	router := gin.Default()

	router.Use(corsMiddleware())

	router.GET("/health", s.healthHandler)
	router.GET("/shorten", s.shortenHandler)
	router.GET("/stats/:shortId", s.statsHandler)
	router.GET("/:shortId", s.redirectHandler)

	return router
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Server) generateShortId(ctx context.Context) string {
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

		exists, err := s.repo.ShortIDExists(ctx, shortId)
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

func (s *Server) shortenHandler(c *gin.Context) {
	originalUrl := c.Query("url")

	if originalUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is missing"})
		return
	}

	if !isValidURL(originalUrl) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL must start with http:// or https://"})
		return
	}

	encryptedURL, err := s.cipher.Encrypt(originalUrl)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt URL"})
		return
	}

	shortId := s.generateShortId(c.Request.Context())
	urlData := storage.URLData{
		ShortID:     shortId,
		OriginalURL: encryptedURL,
		CreatedAt:   time.Now(),
		AccessCount: 0,
	}

	if err := s.repo.Insert(c.Request.Context(), urlData); err != nil {
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

func (s *Server) redirectHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	urlData, err := s.repo.FindForRedirect(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		log.Printf("Failed to query DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if err := s.repo.IncrementAccessCount(c.Request.Context(), shortId); err != nil {
		log.Printf("Failed to update access count: %v", err)
	}

	decrypted, err := s.cipher.Decrypt(urlData.OriginalURL)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt URL"})
		return
	}

	c.Redirect(http.StatusFound, decrypted)
}

func (s *Server) statsHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	urlData, err := s.repo.FindByShortID(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		log.Printf("Failed to query DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	decrypted, err := s.cipher.Decrypt(urlData.OriginalURL)
	if err != nil {
		log.Printf("Decryption error: %v", err)
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

func (s *Server) healthHandler(c *gin.Context) {
	totalUrls, err := s.repo.CountURLs(c.Request.Context())
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
