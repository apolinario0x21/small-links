package http

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

// landingHTML é a landing page, embutida no binário via go:embed para
// manter o deploy de binário único (sem etapa de build de assets).
//
//go:embed static/index.html
var landingHTML []byte

// landingHandler serve a página inicial em GET /.
// @Summary      Landing page
// @Description  Página inicial com formulário de encurtamento.
// @Tags         landing
// @Produce      html
// @Success      200  {string}  string  "HTML da landing page"
// @Router       / [get]
func (s *Server) landingHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", landingHTML)
}
