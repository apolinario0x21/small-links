package http

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// cspNonceKey é a chave sob a qual o nonce da requisição fica no contexto do
// Gin, para o landingHandler carimbar as tags inline com o MESMO valor que o
// header Content-Security-Policy autoriza.
const cspNonceKey = "csp-nonce"

// allowedCORSHeaders inclui Authorization porque DELETE /api/links/:shortId
// autoriza por Bearer token — sem ele o botão "excluir" da landing quebra no
// preflight do navegador. Só vai para origens da allowlist.
const allowedCORSHeaders = "Content-Type, Authorization"

const allowedCORSMethods = "GET, POST, DELETE, OPTIONS"

// corsMiddleware autoriza cross-origin apenas para as origens da allowlist.
//
// Substitui o antigo "Access-Control-Allow-Origin: *", que permitia a
// qualquer site chamar a API com os headers do visitante. Decisões:
//   - allowlist vem de CORS_ALLOWED_ORIGINS (separada por vírgula); vazia =
//     apenas a própria origem da aplicação (scheme + host da requisição), o
//     que cobre a landing embutida sem autorizar terceiros;
//   - origem ausente (curl, server-to-server, navegação normal) ou fora da
//     lista NÃO é bloqueada — apenas não recebe headers CORS. Quem impõe a
//     restrição é o navegador; bloquear aqui quebraria clientes não-browser
//     legítimos sem ganho de segurança.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[strings.ToLower(strings.TrimRight(origin, "/"))] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && originAllowed(c, allowed, origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", allowedCORSMethods)
			c.Header("Access-Control-Allow-Headers", allowedCORSHeaders)
			// A resposta varia conforme o Origin: sem isso um cache
			// compartilhado serviria os headers de uma origem para outra.
			c.Header("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// originAllowed decide se a origem pode receber headers CORS: consta da
// allowlist explícita ou, quando não há allowlist, é a própria origem da
// aplicação.
func originAllowed(c *gin.Context, allowed map[string]bool, origin string) bool {
	normalized := strings.ToLower(strings.TrimRight(origin, "/"))

	if len(allowed) > 0 {
		return allowed[normalized]
	}

	self := strings.ToLower(getScheme(c) + "://" + c.Request.Host)
	return normalized == self
}

// securityHeadersMiddleware aplica os headers de defesa em TODAS as
// respostas. releaseMode liga o HSTS, que só faz sentido onde o serviço é
// realmente servido sobre HTTPS (produção) — em dev sobre http ele apenas
// travaria o navegador do desenvolvedor.
func securityHeadersMiddleware(releaseMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		nonce, err := generateNonce()
		if err != nil {
			// Sem nonce não há como autorizar o inline da landing; falhar a
			// requisição inteira seria pior que servir sem CSP, então
			// seguimos com uma política que não depende de nonce.
			nonce = ""
		}
		c.Set(cspNonceKey, nonce)

		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", contentSecurityPolicy(c.Request.URL.Path, nonce))

		if releaseMode {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// contentSecurityPolicy monta a política da requisição.
//
// A landing é HTML embutido com CSS e JS inline: em vez de liberar
// 'unsafe-inline' (que reabre XSS refletido), autorizamos por nonce, gerado
// por requisição e carimbado nas tags pelo landingHandler.
//
// Exceção: a UI do Swagger é servida por lib de terceiros, com inline que não
// controlamos e não podemos carimbar. Ela recebe uma política relaxada apenas
// nas rotas /swagger — desabilitável em produção via SWAGGER_ENABLED=false.
func contentSecurityPolicy(path, nonce string) string {
	const base = "default-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

	if strings.HasPrefix(path, "/swagger") {
		return "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " + base
	}

	if nonce == "" {
		return "script-src 'self'; style-src 'self'; " + base
	}

	return "script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'nonce-" + nonce + "'; " + base
}

// generateNonce devolve 16 bytes aleatórios em base64 — valor de uso único
// por resposta, como exige o CSP.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
