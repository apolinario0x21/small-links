package http

import (
	"bytes"
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

// landingHTML é a landing page, embutida no binário via go:embed para
// manter o deploy de binário único (sem etapa de build de assets).
//
//go:embed static/index.html
var landingHTML []byte

// nonceTargets são as aberturas de tag inline que recebem o nonce do CSP.
// Carimbar aqui evita liberar 'unsafe-inline' na política.
var nonceTargets = [][]byte{[]byte("<style>"), []byte("<script>")}

// withNonce devolve o HTML com nonce="..." nas tags inline. É uma cópia por
// requisição (o nonce é de uso único), sobre ~30 KB — custo irrelevante
// diante de manter a landing sem 'unsafe-inline'.
func withNonce(html []byte, nonce string) []byte {
	if nonce == "" {
		return html
	}
	out := html
	for _, tag := range nonceTargets {
		replacement := []byte(string(tag[:len(tag)-1]) + ` nonce="` + nonce + `">`)
		out = bytes.ReplaceAll(out, tag, replacement)
	}
	return out
}

// landingHandler serve a página inicial em GET /.
// @Summary      Landing page
// @Description  Página inicial com formulário de encurtamento.
// @Tags         landing
// @Produce      html
// @Success      200  {string}  string  "HTML da landing page"
// @Router       / [get]
func (s *Server) landingHandler(c *gin.Context) {
	nonce := c.GetString(cspNonceKey)
	c.Data(http.StatusOK, "text/html; charset=utf-8", withNonce(landingHTML, nonce))
}
