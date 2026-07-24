package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

// securityRouter monta um router com as Options dadas; o banco mockado não é
// exercido (as asserções são todas sobre headers de /health e /).
func securityRouter(t *testing.T, opts Options) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { mockDB.Close() })

	server := New(storage.NewPostgres(mockDB), testCipher, noopRecorder{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	return server.Router(), mock
}

// doRequestWithOrigin dispara a requisição com o header Origin, como faria um
// navegador em chamada cross-origin.
func doRequestWithOrigin(router *gin.Engine, method, path, origin string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	router.ServeHTTP(w, req)
	return w
}

// --- CORS ---

func TestCORSAllowedOriginFromAllowlist(t *testing.T) {
	router, _ := securityRouter(t, Options{CORSAllowedOrigins: []string{"https://app.exemplo.com"}})

	w := doRequestWithOrigin(router, http.MethodOptions, "/api/shorten", "https://app.exemplo.com")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.exemplo.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the allowed origin", got)
	}
	// Authorization é obrigatório: o DELETE de link usa Bearer token.
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Errorf("Access-Control-Allow-Headers = %q, want it to include Authorization", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "DELETE") {
		t.Errorf("Access-Control-Allow-Methods = %q, want it to include DELETE", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestCORSBlockedOriginGetsNoHeaders(t *testing.T) {
	router, _ := securityRouter(t, Options{CORSAllowedOrigins: []string{"https://app.exemplo.com"}})

	w := doRequestWithOrigin(router, http.MethodGet, "/health", "https://evil.exemplo.com")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a non-allowed origin", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); got != "" {
		t.Errorf("Access-Control-Allow-Headers = %q, want empty for a non-allowed origin", got)
	}
}

// A origem fora da allowlist não é bloqueada: quem impede a leitura da
// resposta é o navegador. Clientes não-browser seguem funcionando.
func TestCORSBlockedOriginStillReachesHandler(t *testing.T) {
	router, mock := securityRouter(t, Options{CORSAllowedOrigins: []string{"https://app.exemplo.com"}})
	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := doRequestWithOrigin(router, http.MethodGet, "/health", "https://evil.exemplo.com")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (CORS não deve bloquear a requisição)", w.Code)
	}
}

func TestCORSNoOriginHeader(t *testing.T) {
	router, mock := securityRouter(t, Options{})
	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := doRequest(router, http.MethodGet, "/health")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty when there is no Origin", got)
	}
}

func TestCORSDefaultsToOwnOrigin(t *testing.T) {
	router, _ := securityRouter(t, Options{})

	// httptest.NewRequest usa example.com como host da requisição.
	self := doRequestWithOrigin(router, http.MethodOptions, "/api/shorten", "http://example.com")
	if got := self.Header().Get("Access-Control-Allow-Origin"); got != "http://example.com" {
		t.Errorf("own origin: Access-Control-Allow-Origin = %q, want http://example.com", got)
	}

	other := doRequestWithOrigin(router, http.MethodOptions, "/api/shorten", "https://outro.exemplo.com")
	if got := other.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("other origin: Access-Control-Allow-Origin = %q, want empty", got)
	}
}

// --- Headers de segurança ---

func TestSecurityHeadersPresent(t *testing.T) {
	router, mock := securityRouter(t, Options{})
	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := doRequest(router, http.MethodGet, "/health")

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, value := range want {
		if got := w.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, want default-src 'self' e frame-ancestors 'none'", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("Content-Security-Policy = %q, não deve liberar unsafe-inline fora do Swagger", csp)
	}
	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("Strict-Transport-Security = %q, want empty fora do modo release", hsts)
	}
}

func TestHSTSOnlyInReleaseMode(t *testing.T) {
	router, mock := securityRouter(t, Options{ReleaseMode: true})
	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := doRequest(router, http.MethodGet, "/health")

	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("Strict-Transport-Security = %q", got)
	}
}

// A landing usa CSS e JS inline: o nonce do header precisa aparecer nas tags,
// senão o navegador bloqueia a página inteira.
func TestLandingCSPNonceMatchesInlineTags(t *testing.T) {
	router, _ := securityRouter(t, Options{})

	w := doRequest(router, http.MethodGet, "/")

	csp := w.Header().Get("Content-Security-Policy")
	start := strings.Index(csp, "'nonce-")
	if start < 0 {
		t.Fatalf("CSP sem nonce: %q", csp)
	}
	nonce := csp[start+len("'nonce-"):]
	nonce = nonce[:strings.Index(nonce, "'")]

	body := w.Body.String()
	for _, tag := range []string{`<style nonce="`, `<script nonce="`} {
		if !strings.Contains(body, tag+nonce+`">`) {
			t.Errorf("landing sem %s%s\"> — o inline seria bloqueado pelo CSP", tag, nonce)
		}
	}
}

// Nonces são de uso único: duas respostas não podem repetir o mesmo valor.
func TestCSPNonceIsPerRequest(t *testing.T) {
	router, _ := securityRouter(t, Options{})

	first := doRequest(router, http.MethodGet, "/").Header().Get("Content-Security-Policy")
	second := doRequest(router, http.MethodGet, "/").Header().Get("Content-Security-Policy")

	if first == second {
		t.Error("CSP idêntico em duas requisições: o nonce não está sendo regerado")
	}
}
