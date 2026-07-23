// Package http contém os handlers, middleware e rotas da API.
package http

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/metrics"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skip2/go-qrcode"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// ClickRecorder registra eventos de clique de forma assíncrona. Satisfeito
// por *analytics.Recorder; um no-op serve para testes e para desabilitar.
type ClickRecorder interface {
	Record(c analytics.Click)
}

// URLChecker verifica se uma URL é maliciosa. Satisfeito por
// *safebrowsing.Client; nil desabilita a verificação. Um erro não-nil sinaliza
// falha da própria checagem (o handler faz fail-open).
type URLChecker interface {
	Malicious(ctx context.Context, rawURL string) (bool, error)
}

// Server agrega as dependências dos handlers.
type Server struct {
	repo            storage.Repository
	cipher          *crypto.Cipher
	recorder        ClickRecorder
	checker         URLChecker
	logger          *slog.Logger
	swaggerEnabled  bool
	trustedPlatform string
}

func New(repo storage.Repository, cipher *crypto.Cipher, recorder ClickRecorder, checker URLChecker, logger *slog.Logger, swaggerEnabled bool, trustedPlatform string) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		repo:            repo,
		cipher:          cipher,
		recorder:        recorder,
		checker:         checker,
		logger:          logger,
		swaggerEnabled:  swaggerEnabled,
		trustedPlatform: trustedPlatform,
	}
}

func (s *Server) Router() *gin.Engine {
	router := gin.Default()

	// Fonte do IP do cliente. Todo consumidor (rate limiter, analytics) usa
	// c.ClientIP(), então a decisão de confiança vive só aqui.
	//
	// TRUSTED_PLATFORM=cloudflare: no Render, a cadeia é
	// visitante → Cloudflare → proxy interno (10.x) → app. Confiar apenas em
	// faixas privadas faz o Gin devolver o IP da BORDA Cloudflare como cliente
	// (104.x/172.71.x), geolocalizando todo mundo como US. Com PlatformCloudflare
	// o Gin lê CF-Connecting-IP, que a borda injeta (sobrescrevendo o que o
	// visitante mandar) — logo não é forjável NESSA topologia, onde o tráfego
	// externo não tem como alcançar o app sem passar pela Cloudflare.
	//
	// Fora dela o header seria trivialmente forjável (spoof de rate limit e de
	// geo), por isso é opt-in por env e jamais o default. Vazio = modo padrão:
	// SetTrustedProxies com faixas privadas, que preserva o docker compose local.
	if s.trustedPlatform == config.PlatformCloudflare {
		router.TrustedPlatform = gin.PlatformCloudflare
	} else if err := router.SetTrustedProxies([]string{
		"127.0.0.1", "::1",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8",
	}); err != nil {
		s.logger.Error("failed to set trusted proxies", "error", err)
	}

	router.Use(metricsMiddleware(), corsMiddleware())

	createLimiter := newIPRateLimiter(rateLimitPerMinute, rateLimitBurst).middleware()

	// Landing page na raiz. Não conflita com o catch-all /:shortId (rota
	// estática "/" vs. param de um segmento) nem com os aliases (o regex de
	// alias exige 3+ chars, então "/" jamais seria um alias válido).
	router.GET("/", s.landingHandler)

	router.GET("/health", s.healthHandler)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	router.GET("/shorten", createLimiter, s.shortenHandler)
	router.POST("/api/shorten", createLimiter, s.apiShortenHandler)
	router.DELETE("/api/links/:shortId", createLimiter, s.deleteHandler)
	router.GET("/stats/:shortId", s.statsHandler)
	router.GET("/qr/:shortId", s.qrHandler)

	// UI interativa do Swagger/OpenAPI. Registrada antes da rota catch-all
	// /:shortId e desabilitável via SWAGGER_ENABLED=false (produção).
	if s.swaggerEnabled {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	router.GET("/:shortId", s.redirectHandler)

	return router
}

// metricsMiddleware observa a latência de cada requisição rotulada por
// método, rota (padrão registrado, não o path bruto) e status.
func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		metrics.RequestDuration.WithLabelValues(
			c.Request.Method, route, strconv.Itoa(c.Writer.Status()),
		).Observe(time.Since(start).Seconds())
	}
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

// aliasRegex valida o alias customizado: 3-30 chars alfanuméricos, hífen
// ou underscore.
var aliasRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,30}$`)

// reservedAliases são os primeiros segmentos de rota que um alias não pode
// assumir, para não sombrear endpoints do serviço.
var reservedAliases = map[string]bool{
	"health":  true,
	"shorten": true,
	"stats":   true,
	"api":     true,
	"metrics": true,
	"qr":      true,
	"swagger": true,
}

// ShortenRequest é o corpo do POST /api/shorten.
type ShortenRequest struct {
	URL           string `json:"url" example:"https://www.exemplo.com/pagina"`
	CustomAlias   string `json:"custom_alias,omitempty" example:"promo"`
	ExpiresInDays *int   `json:"expires_in_days,omitempty" example:"30"`
}

// shortenHandler mantém o contrato legado: GET /shorten?url=... com 200.
// @Summary      Encurta uma URL (endpoint legado)
// @Description  Variante GET mantida por compatibilidade; delega à mesma lógica do POST.
// @Tags         shorten
// @Produce      json
// @Param        url  query     string  true  "URL original (http/https)"
// @Success      200  {object}  ShortenResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      422  {object}  ErrorResponse  "URL bloqueada: maliciosa (phishing/malware)"
// @Failure      429  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /shorten [get]
func (s *Server) shortenHandler(c *gin.Context) {
	originalUrl := c.Query("url")

	if originalUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is missing"})
		return
	}

	s.createShortURL(c, originalUrl, "", nil, http.StatusOK, false)
}

// apiShortenHandler é a variante nova: POST /api/shorten com body JSON e 201.
// @Summary      Encurta uma URL
// @Description  Cria um short link. Campos opcionais: custom_alias e expires_in_days. Se a URL já existir, responde 200 com "existing": true.
// @Tags         shorten
// @Accept       json
// @Produce      json
// @Param        request  body      ShortenRequest  true  "URL e opções"
// @Success      201      {object}  ShortenResponse  "Short link criado"
// @Success      200      {object}  ShortenResponse  "URL já existente (dedup)"
// @Failure      400      {object}  ErrorResponse    "Body ou URL inválidos"
// @Failure      409      {object}  ErrorResponse    "Alias já em uso ou reservado"
// @Failure      422      {object}  ErrorResponse    "URL bloqueada: maliciosa (phishing/malware)"
// @Failure      500      {object}  ErrorResponse
// @Router       /api/shorten [post]
func (s *Server) apiShortenHandler(c *gin.Context) {
	var req ShortenRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body must be JSON with a non-empty \"url\" field"})
		return
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil {
		if *req.ExpiresInDays <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_in_days must be a positive integer"})
			return
		}
		t := time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}

	s.createShortURL(c, req.URL, req.CustomAlias, expiresAt, http.StatusCreated, true)
}

func (s *Server) createShortURL(c *gin.Context, originalUrl, alias string, expiresAt *time.Time, successStatus int, includeShortID bool) {
	if err := validateURL(originalUrl, c.Request.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verificação de URL maliciosa (Safe Browsing), antes do dedup e do
	// insert. Falha da API é fail-open (permite criar), com log warn e métrica.
	if s.checker != nil {
		switch blocked, err := s.checker.Malicious(c.Request.Context(), originalUrl); {
		case err != nil:
			s.logger.Warn("safe browsing check failed, allowing (fail-open)", "error", err)
			metrics.SafeBrowsingErrorsTotal.Inc()
		case blocked:
			metrics.SafeBrowsingBlockedTotal.Inc()
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "URL bloqueada: identificada como potencialmente maliciosa (phishing/malware)"})
			return
		}
	}

	urlHash := s.cipher.Hash(originalUrl)

	if alias != "" {
		// Alias explícito: valida o formato e as rotas reservadas antes de
		// tentar gravar. Não passa por dedup — o usuário quer este alias.
		if !aliasRegex.MatchString(alias) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "custom_alias must match ^[a-zA-Z0-9_-]{3,30}$"})
			return
		}
		if reservedAliases[strings.ToLower(alias)] {
			c.JSON(http.StatusConflict, gin.H{"error": "custom_alias is reserved"})
			return
		}
	} else {
		// Dedup: se a URL já foi encurtada, reaproveita o short_id existente.
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
			metrics.ShortensTotal.Inc()
			c.JSON(http.StatusOK, response)
			return
		} else if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Error("failed to look up URL hash", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
			return
		}
	}

	encryptedURL, err := s.cipher.Encrypt(originalUrl)
	if err != nil {
		s.logger.Error("failed to encrypt URL", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt URL"})
		return
	}

	// Token de gerenciamento: gerado a cada criação nova; só o SHA-256 é
	// persistido. O token em claro é devolvido UMA ÚNICA VEZ no response
	// (nunca no reaproveitamento por dedup — só o criador original o tem).
	managementToken, err := crypto.GenerateToken()
	if err != nil {
		s.logger.Error("failed to generate management token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
		return
	}
	tokenHash := crypto.TokenSHA256(managementToken)

	writeSuccess := func(shortId string, createdAt time.Time) {
		scheme := getScheme(c)
		response := gin.H{
			"original_url":     originalUrl,
			"short_url":        scheme + "://" + c.Request.Host + "/" + shortId,
			"created_at":       createdAt,
			"management_token": managementToken,
		}
		if includeShortID {
			response["short_id"] = shortId
		}
		if expiresAt != nil {
			response["expires_at"] = *expiresAt
		}
		metrics.ShortensTotal.Inc()
		c.JSON(successStatus, response)
	}

	// Alias fixo: uma única tentativa; colisão vira 409 Conflict.
	if alias != "" {
		urlData := storage.URLData{ShortID: alias, OriginalURL: encryptedURL, URLHash: urlHash, CreatedAt: time.Now(), ExpiresAt: expiresAt, ManagementTokenHash: tokenHash}
		switch err := s.repo.Insert(c.Request.Context(), urlData); {
		case err == nil:
			writeSuccess(alias, urlData.CreatedAt)
		case errors.Is(err, storage.ErrDuplicate):
			c.JSON(http.StatusConflict, gin.H{"error": "custom_alias already in use"})
		case errors.Is(err, storage.ErrValueTooLong):
			// Rede de segurança caso validação e schema divirjam de novo.
			c.JSON(http.StatusBadRequest, gin.H{"error": "custom_alias is too long"})
		default:
			s.logger.Error("failed to insert URL", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
		}
		return
	}

	// A unicidade do short_id gerado é garantida pela constraint UNIQUE: em
	// caso de colisão, gera outro candidato, até 3 tentativas.
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		shortId, err := generateShortID()
		if err != nil {
			s.logger.Error("failed to generate short id", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
			return
		}

		urlData := storage.URLData{ShortID: shortId, OriginalURL: encryptedURL, URLHash: urlHash, CreatedAt: time.Now(), ExpiresAt: expiresAt, ManagementTokenHash: tokenHash}
		switch err := s.repo.Insert(c.Request.Context(), urlData); {
		case err == nil:
			writeSuccess(shortId, urlData.CreatedAt)
			return
		case errors.Is(err, storage.ErrDuplicate):
			s.logger.Warn("short id collision, retrying", "short_id", shortId, "attempt", attempt)
		default:
			s.logger.Error("failed to insert URL", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
			return
		}
	}

	s.logger.Error("exhausted short id attempts", "attempts", maxAttempts)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to shorten URL"})
}

// dummyTokenHash é um SHA-256 fixo (64 chars) usado como alvo da comparação
// em tempo constante quando o link não existe ou não tem token — mantém o
// timing e o status uniformes, sem vazar existência.
const dummyTokenHash = "0000000000000000000000000000000000000000000000000000000000000000"

// bearerToken extrai o token de "Authorization: Bearer <token>".
func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	h := c.GetHeader("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// deleteHandler desativa (soft delete) um link mediante posse do token de
// gerenciamento — autorização por segredo, sem identidade.
// @Summary      Desativa um short link
// @Description  Soft delete via token de gerenciamento (Authorization: Bearer <token>). Resposta 403 uniforme quando não autorizado — não revela se o short_id existe. Analytics preservado; redirect/QR passam a 410.
// @Tags         links
// @Produce      json
// @Param        shortId        path    string  true  "Identificador do short link"
// @Param        Authorization  header  string  true  "Bearer <management_token>"
// @Success      204  "Link desativado"
// @Failure      403  {object}  ErrorResponse  "Token ausente ou inválido (uniforme)"
// @Failure      500  {object}  ErrorResponse
// @Router       /api/links/{shortId} [delete]
func (s *Server) deleteHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	token := bearerToken(c)
	if token == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid or missing management token"})
		return
	}

	hash, exists, err := s.repo.ManagementHash(c.Request.Context(), shortId)
	if err != nil {
		s.logger.Error("failed to load management hash", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Comparação em tempo constante SEMPRE, contra o hash real ou um dummy
	// (link inexistente/sem token) — comparação normal vazaria por timing.
	manageable := exists && hash != ""
	stored := hash
	if !manageable {
		stored = dummyTokenHash
	}
	provided := crypto.TokenSHA256(token)
	match := subtle.ConstantTimeCompare([]byte(provided), []byte(stored)) == 1

	if !manageable || !match {
		// 403 uniforme: inexistente, sem token de gestão, ou token errado são
		// indistinguíveis — não vaza a existência do short_id.
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid or missing management token"})
		return
	}

	deleted, err := s.repo.SoftDelete(c.Request.Context(), shortId)
	if err != nil {
		s.logger.Error("failed to soft delete link", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if deleted {
		metrics.LinksDeletedTotal.Inc()
	}
	c.Status(http.StatusNoContent)
}

// redirectHandler resolve o short link e redireciona para a URL original.
// @Summary      Redireciona um short link
// @Description  Responde 302 para a URL original. 404 se inexistente, 410 se expirado ou deletado.
// @Tags         redirect
// @Produce      json
// @Param        shortId  path  string  true  "Identificador do short link"
// @Success      302  "Redirect para a URL original"
// @Failure      404  {object}  ErrorResponse
// @Failure      410  {object}  ErrorResponse  "Link expirado ou desativado"
// @Failure      500  {object}  ErrorResponse
// @Router       /{shortId} [get]
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

	if urlData.DeletedAt != nil {
		c.JSON(http.StatusGone, gin.H{"error": "Short URL has been deleted"})
		return
	}

	if urlData.ExpiresAt != nil && time.Now().After(*urlData.ExpiresAt) {
		c.JSON(http.StatusGone, gin.H{"error": "Short URL has expired"})
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
	metrics.RedirectsTotal.Inc()

	// Registra o clique após responder o 302; o Record é não-bloqueante.
	// O IP segue em claro apenas dentro do processo: o Recorder resolve o
	// país e gera o ip_hash, sem jamais persistir o IP (ver nota LGPD).
	if s.recorder != nil {
		s.recorder.Record(analytics.Click{
			ShortID:   shortId,
			Referrer:  c.Request.Referer(),
			UserAgent: c.Request.UserAgent(),
			IP:        c.ClientIP(),
		})
	}
}

// statsHandler devolve estatísticas de acesso de um short link.
// @Summary      Estatísticas de um short link
// @Description  Retorna access_count, total_clicks, clicks_per_day (30 dias), top_referrers (top 5), top_countries e devices. Bots (is_bot) ficam fora de todas as agregações; país/device não classificado aparece como "unknown". top_countries lista todos os países (sem top-5), de modo que a soma de top_countries e a soma de devices batem com total_clicks.
// @Tags         stats
// @Produce      json
// @Param        shortId  path      string  true  "Identificador do short link"
// @Success      200  {object}  StatsResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /stats/{shortId} [get]
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

	clickStats, err := s.repo.ClickStats(c.Request.Context(), shortId)
	if err != nil {
		s.logger.Error("failed to query click stats", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		// Campos mantidos por compatibilidade.
		"short_id":     shortId,
		"original_url": decrypted,
		"created_at":   urlData.CreatedAt,
		"access_count": urlData.AccessCount,
		// Analytics (bots excluídos das agregações).
		"total_clicks":   clickStats.TotalClicks,
		"clicks_per_day": clickStats.ClicksPerDay,
		"top_referrers":  clickStats.TopReferrers,
		"top_countries":  clickStats.TopCountries,
		"devices":        clickStats.Devices,
	})
}

// qrHandler devolve um PNG com o QR code do short_url. Confirma que o
// short link existe antes de gerar.
// @Summary      QR code de um short link
// @Description  Gera o PNG do short_url. Confirma que o link existe antes de gerar. 410 se deletado.
// @Tags         qr
// @Produce      png
// @Param        shortId  path  string  true  "Identificador do short link"
// @Success      200  {file}    binary         "Imagem PNG"
// @Failure      404  {object}  ErrorResponse
// @Failure      410  {object}  ErrorResponse  "Link desativado"
// @Failure      500  {object}  ErrorResponse
// @Router       /qr/{shortId} [get]
func (s *Server) qrHandler(c *gin.Context) {
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
	if urlData.DeletedAt != nil {
		c.JSON(http.StatusGone, gin.H{"error": "Short URL has been deleted"})
		return
	}

	shortUrl := getScheme(c) + "://" + c.Request.Host + "/" + shortId
	png, err := qrcode.Encode(shortUrl, qrcode.Medium, 256)
	if err != nil {
		s.logger.Error("failed to generate QR code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	c.Data(http.StatusOK, "image/png", png)
}

// healthHandler é o health check do serviço.
// @Summary      Health check
// @Description  Retorna status do serviço, total de URLs e timestamp.
// @Tags         health
// @Produce      json
// @Success      200  {object}  HealthResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /health [get]
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
