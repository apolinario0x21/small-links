package http

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/metrics"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

// passwordHTML é a tela de senha, embutida como as demais páginas para
// preservar o deploy de binário único. É um template (e não bytes servidos
// direto) porque precisa do nonce do CSP e da mensagem de erro — ambos
// escapados pelo html/template.
//
//go:embed static/password.html
var passwordHTML string

var passwordTemplate = template.Must(template.New("password").Parse(passwordHTML))

// accessCookieName é o cookie de acesso a link protegido. O escopo real vem
// do Path (/<shortId>): o navegador só o envia para o link a que pertence.
const accessCookieName = "sl_access"

// errWrongPassword é a mensagem exibida na tela após senha incorreta.
// #nosec G101 -- texto de interface, não credencial: nenhuma senha é embutida no binário.
const errWrongPassword = "senha incorreta"

// passwordPageData alimenta o template da tela de senha. Note que a URL de
// destino NUNCA entra aqui — a página existe justamente para não revelá-la
// antes da autenticação.
type passwordPageData struct {
	Nonce  string
	Action string
	Error  string
}

// wantsHTML decide entre a tela de senha e o 401 JSON. Navegador manda
// Accept com text/html; curl e clientes de API, não.
func wantsHTML(c *gin.Context) bool {
	return strings.Contains(c.GetHeader("Accept"), "text/html")
}

// renderPasswordPage devolve a tela de senha (ou o 401 JSON equivalente,
// conforme o Accept). status é 200 na primeira exibição e 401 após erro.
func (s *Server) renderPasswordPage(c *gin.Context, shortID, errMsg string, status int) {
	if !wantsHTML(c) {
		body := gin.H{"error": "link protegido por senha"}
		if errMsg != "" {
			body["error"] = errMsg
		}
		c.JSON(http.StatusUnauthorized, body)
		return
	}

	data := passwordPageData{
		Nonce:  c.GetString(cspNonceKey),
		Action: "/" + shortID,
		Error:  errMsg,
	}

	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")
	// Sobrescreve a CSP do middleware: esta página precisa poder enviar o
	// formulário para um destino externo (ver passwordPageCSP).
	c.Header("Content-Security-Policy", passwordPageCSP(data.Nonce))
	// Cache de tela de senha não faz sentido e atrapalha o pós-login.
	c.Header("Cache-Control", "no-store")
	if err := passwordTemplate.Execute(c.Writer, data); err != nil {
		s.logger.Error("failed to render password page", "error", err)
	}
}

// hasAccess informa se a requisição traz cookie de acesso válido para este
// short_id. Assinatura, vínculo com o link e expiração são verificados em
// crypto.VerifyAccessToken.
func (s *Server) hasAccess(c *gin.Context, shortID string) bool {
	token, err := c.Cookie(accessCookieName)
	if err != nil || token == "" {
		return false
	}
	return s.cipher.VerifyAccessToken(token, shortID, time.Now()) == nil
}

// issueAccessCookie emite o cookie assinado após a senha correta.
// HttpOnly (JS nunca lê), Secure em produção, SameSite=Lax e Path restrito
// ao próprio link — o cookie de um link não vaza para outro.
func (s *Server) issueAccessCookie(c *gin.Context, shortID string) {
	token := s.cipher.SignAccessToken(shortID, time.Now().Add(crypto.AccessTokenTTL))

	c.SetSameSite(http.SameSiteLaxMode)
	// #nosec G124 -- Secure é condicional de propósito: em release o cookie é
	// Secure; no Compose local (http) marcá-lo Secure impediria o navegador de
	// enviá-lo, quebrando o fluxo em desenvolvimento. HttpOnly e SameSite são
	// sempre aplicados.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     accessCookieName,
		Value:    token,
		Path:     "/" + shortID,
		MaxAge:   int(crypto.AccessTokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.opts.ReleaseMode,
		SameSite: http.SameSiteLaxMode,
	})
}

// submittedPassword lê a senha do form (navegador) ou do header X-Password
// (clientes de API).
func submittedPassword(c *gin.Context) string {
	if pw := c.PostForm("password"); pw != "" {
		return pw
	}
	return c.GetHeader("X-Password")
}

// passwordHandler recebe a senha de um link protegido e, se correta, emite o
// cookie de acesso e redireciona.
// @Summary      Envia a senha de um link protegido
// @Description  Aceita `password` via form ou header `X-Password`. Senha correta emite o cookie de acesso assinado (1h, HttpOnly, Path do link) e responde 302 para a URL original, na mesma resposta. Limitado a 5 tentativas por minuto POR LINK.
// @Tags         redirect
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        shortId     path      string  true   "Identificador do short link"
// @Param        password    formData  string  false  "Senha do link"
// @Param        X-Password  header    string  false  "Senha do link (alternativa ao form)"
// @Success      302  "Redirect para a URL original"
// @Failure      401  {object}  ErrorResponse  "Senha ausente ou incorreta"
// @Failure      404  {object}  ErrorResponse  "Link inexistente ou sem senha"
// @Failure      410  {object}  ErrorResponse  "Link expirado ou desativado"
// @Failure      429  {object}  ErrorResponse  "Tentativas excedidas para este link"
// @Failure      500  {object}  ErrorResponse
// @Router       /{shortId} [post]
func (s *Server) passwordHandler(c *gin.Context) {
	shortId := c.Param("shortId")

	urlData, ok := s.loadRedirectTarget(c, shortId)
	if !ok {
		return
	}

	// Link sem senha não tem o que autenticar.
	if urlData.PasswordHash == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
		return
	}

	metrics.PasswordAttemptsTotal.Inc()

	if !crypto.CheckPassword(urlData.PasswordHash, submittedPassword(c)) {
		metrics.PasswordFailuresTotal.Inc()
		s.renderPasswordPage(c, shortId, errWrongPassword, http.StatusUnauthorized)
		return
	}

	s.issueAccessCookie(c, shortId)
	// 302 direto ao destino, para navegador e cliente de API. O bloqueio que
	// existia aqui não era do código do redirect, e sim da diretiva
	// `form-action` da CSP — corrigida em passwordPageCSP.
	s.completeRedirect(c, urlData)
}

// loadRedirectTarget carrega o link e aplica, na ordem, as condições que
// encerram a requisição sem revelar nada sobre o destino: inexistente (404),
// deletado (410) e expirado (410).
//
// A PRECEDÊNCIA É DELIBERADA: expiração e soft delete vêm ANTES da senha, de
// modo que um link morto responde 410 sem nunca exibir a tela de senha — não
// faria sentido pedir a senha de algo que não vai abrir de todo jeito.
func (s *Server) loadRedirectTarget(c *gin.Context, shortId string) (storage.URLData, bool) {
	urlData, err := s.repo.FindForRedirect(c.Request.Context(), shortId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
			return storage.URLData{}, false
		}
		s.logger.Error("failed to query DB", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return storage.URLData{}, false
	}

	if urlData.DeletedAt != nil {
		c.JSON(http.StatusGone, gin.H{"error": "Short URL has been deleted"})
		return storage.URLData{}, false
	}

	if urlData.ExpiresAt != nil && time.Now().After(*urlData.ExpiresAt) {
		c.JSON(http.StatusGone, gin.H{"error": "Short URL has expired"})
		return storage.URLData{}, false
	}

	return urlData, true
}

// completeRedirect executa o redirect autorizado: conta o acesso, decifra e
// responde 302, registrando o clique. Só é chamado quando o acesso está
// liberado — a exibição da tela de senha NÃO passa por aqui, então não
// polui o analytics.
func (s *Server) completeRedirect(c *gin.Context, urlData storage.URLData) {
	shortId := urlData.ShortID

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
