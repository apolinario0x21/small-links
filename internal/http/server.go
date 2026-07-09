// Package http contém os handlers, middleware e rotas da API.
package http

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
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
	logger *slog.Logger
}

func New(repo storage.Repository, cipher *crypto.Cipher, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{repo: repo, cipher: cipher, logger: logger}
}

func (s *Server) Router() *gin.Engine {
	router := gin.Default()

	// Atrás do proxy do Railway as requisições chegam da rede interna;
	// confiar apenas em faixas privadas permite que ClientIP() leia o
	// X-Forwarded-For do proxy sem aceitar spoofing de clientes externos.
	if err := router.SetTrustedProxies([]string{
		"127.0.0.1", "::1",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8",
	}); err != nil {
		s.logger.Error("failed to set trusted proxies", "error", err)
	}

	router.Use(corsMiddleware())

	createLimiter := newIPRateLimiter(rateLimitPerMinute, rateLimitBurst).middleware()

	router.GET("/health", s.healthHandler)
	router.GET("/shorten", createLimiter, s.shortenHandler)
	router.POST("/api/shorten", createLimiter, s.apiShortenHandler)
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

// generateShortID gera um candidato de 6 caracteres; a unicidade é
// garantida pela constraint UNIQUE no insert, não por consulta prévia.
func generateShortID() (string, error) {
	b := make([]rune, 6)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(lettersRune))))
		if err != nil {
			return "", err
		}
		b[i] = lettersRune[num.Int64()]
	}
	return string(b), nil
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

var (
	errInvalidURL       = errors.New("URL must be a valid http:// or https:// URL")
	errSelfReferenceURL = errors.New("URL must not point to this service")
)

// validateURL exige scheme http/https, host não vazio e rejeita URLs que
// apontem para o próprio serviço (evita loop de redirecionamento).
func validateURL(rawURL, requestHost string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return errInvalidURL
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errInvalidURL
	}

	if parsed.Host == "" {
		return errInvalidURL
	}

	if strings.EqualFold(parsed.Host, requestHost) {
		return errSelfReferenceURL
	}

	return nil
}

type shortenRequest struct {
	URL string `json:"url"`
}

// shortenHandler mantém o contrato legado: GET /shorten?url=... com 200.
func (s *Server) shortenHandler(c *gin.Context) {
	originalUrl := c.Query("url")

	if originalUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is missing"})
		return
	}

	s.createShortURL(c, originalUrl, http.StatusOK, false)
}

// apiShortenHandler é a variante nova: POST /api/shorten com body JSON e 201.
func (s *Server) apiShortenHandler(c *gin.Context) {
	var req shortenRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body must be JSON with a non-empty \"url\" field"})
		return
	}

	s.createShortURL(c, req.URL, http.StatusCreated, true)
}

func (s *Server) createShortURL(c *gin.Context, originalUrl string, successStatus int, includeShortID bool) {
	if err := validateURL(originalUrl, c.Request.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Dedup: se a URL já foi encurtada, reaproveita o short_id existente.
	urlHash := s.cipher.Hash(originalUrl)
	if existing, err := s.repo.FindByURLHash(c.Request.Context(), urlHash); err == nil {
		scheme := getScheme(c)
		response := gin.H{
			"original_url": originalUrl,
			"short_url":    scheme + "://" + c.Request.Host + "/" + existing.ShortID,
			"created_at":   existing.CreatedAt,
			"existing":     true,
		}
		if includeShortID {
			response["short_id"] = existing.ShortID
		}
		c.JSON(http.StatusOK, response)
		return
	} else if !errors.Is(err, storage.ErrNotFound) {
		s.logger.Error("failed to look up URL hash", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
		return
	}

	encryptedURL, err := s.cipher.Encrypt(originalUrl)
	if err != nil {
		s.logger.Error("failed to encrypt URL", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt URL"})
		return
	}

	// A unicidade do short_id é garantida pela constraint UNIQUE: em caso
	// de colisão, gera outro candidato, até 3 tentativas.
	const maxAttempts = 3
	var urlData storage.URLData
	inserted := false
	for attempt := 1; attempt <= maxAttempts && !inserted; attempt++ {
		shortId, err := generateShortID()
		if err != nil {
			s.logger.Error("failed to generate short id", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
			return
		}

		urlData = storage.URLData{
			ShortID:     shortId,
			OriginalURL: encryptedURL,
			URLHash:     urlHash,
			CreatedAt:   time.Now(),
			AccessCount: 0,
		}

		switch err := s.repo.Insert(c.Request.Context(), urlData); {
		case err == nil:
			inserted = true
		case errors.Is(err, storage.ErrDuplicate):
			s.logger.Warn("short id collision, retrying", "short_id", shortId, "attempt", attempt)
		default:
			s.logger.Error("failed to insert URL", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
			return
		}
	}

	if !inserted {
		s.logger.Error("exhausted short id attempts", "attempts", maxAttempts)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
		return
	}

	shortId := urlData.ShortID

	scheme := getScheme(c)
	host := c.Request.Host
	shortUrl := scheme + "://" + host + "/" + shortId

	response := gin.H{
		"original_url": originalUrl,
		"short_url":    shortUrl,
		"created_at":   urlData.CreatedAt,
	}
	if includeShortID {
		response["short_id"] = shortId
	}

	c.JSON(successStatus, response)
}

func (s *Server) redirectHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	urlData, err := s.repo.FindForRedirect(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return
		}
		s.logger.Error("failed to query DB", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if err := s.repo.IncrementAccessCount(c.Request.Context(), shortId); err != nil {
		s.logger.Warn("failed to update access count", "error", err)
	}

	decrypted, err := s.cipher.Decrypt(urlData.OriginalURL)
	if err != nil {
		s.logger.Error("failed to decrypt URL", "error", err)
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
		s.logger.Error("failed to query DB", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	decrypted, err := s.cipher.Decrypt(urlData.OriginalURL)
	if err != nil {
		s.logger.Error("failed to decrypt URL", "error", err)
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
		s.logger.Error("failed to query total URLs", "error", err)
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
