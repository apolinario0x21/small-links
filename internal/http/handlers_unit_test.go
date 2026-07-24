package http

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

// Testes de unidade dos caminhos que os fluxos felizes não alcançam: erro de
// banco no meio da requisição, decifragem que falha, helpers puros.

// --- getScheme ---

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		tls     bool
		want    string
	}{
		{"sem pistas", nil, false, "http"},
		{"X-Forwarded-Proto: https", map[string]string{"X-Forwarded-Proto": "https"}, false, "https"},
		{"X-Forwarded-Proto: http", map[string]string{"X-Forwarded-Proto": "http"}, false, "http"},
		{"X-Forwarded-Ssl: on", map[string]string{"X-Forwarded-Ssl": "on"}, false, "https"},
		{"conexão TLS direta", nil, true, "https"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.headers {
				c.Request.Header.Set(k, v)
			}
			if tc.tls {
				c.Request.TLS = &tls.ConnectionState{}
			}

			if got := getScheme(c); got != tc.want {
				t.Errorf("getScheme() = %q, want %q", got, tc.want)
			}
		})
	}
}

// O short_url devolvido acompanha o esquema detectado — atrás do proxy do
// Render o link precisa sair https, não http.
func TestShortURLUsesForwardedScheme(t *testing.T) {
	router, mock := setupTest(t)
	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/shorten", strings.NewReader(`{"url":"https://www.example.com/x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	body := decodeBody(t, w)
	if short, _ := body["short_url"].(string); !strings.HasPrefix(short, "https://") {
		t.Errorf("short_url = %q, want prefixo https://", short)
	}
	expectations(t, mock)
}

// --- validateURL ---

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		host    string
		wantErr error
	}{
		{"https válida", "https://exemplo.com/p", "curto.io", nil},
		{"http válida", "http://exemplo.com", "curto.io", nil},
		{"sem esquema", "exemplo.com", "curto.io", errInvalidURL},
		{"esquema ftp", "ftp://exemplo.com", "curto.io", errInvalidURL},
		{"javascript", "javascript:alert(1)", "curto.io", errInvalidURL},
		{"host vazio", "https://", "curto.io", errInvalidURL},
		{"aponta para o serviço", "https://curto.io/abc", "curto.io", errSelfReferenceURL},
		{"auto-referência com caixa diferente", "https://CURTO.io/abc", "curto.io", errSelfReferenceURL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateURL(tc.raw, tc.host)
			if err != tc.wantErr {
				t.Errorf("validateURL() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// --- Erros de banco nos handlers ---

func TestStatsDBErrorReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/stats/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

// Falha ao agregar cliques não pode devolver um payload de stats pela metade.
func TestStatsClickStatsErrorReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("abc123", encrypt("https://www.example.com"), time.Now(), 1))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM click_events`).WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/stats/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

// Ciphertext ilegível (chave trocada, registro corrompido) vira 500 — nunca
// um redirect para lixo.
func TestStatsUndecryptableURLReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("abc123", "nao-e-ciphertext-valido", time.Now(), 0))

	w := doRequest(router, http.MethodGet, "/stats/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

func TestRedirectUndecryptableURLReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(redirectQueryRegex).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("abc123", "nao-e-ciphertext-valido", 0, nil, nil, nil))
	mock.ExpectExec(`UPDATE urls SET access_count = access_count \+ 1`).
		WithArgs("abc123").WillReturnResult(sqlmock.NewResult(0, 1))

	w := doRequest(router, http.MethodGet, "/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q; não pode redirecionar com URL ilegível", loc)
	}
	expectations(t, mock)
}

func TestRedirectDBErrorReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(redirectQueryRegex).WithArgs("abc123").WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

func TestQRCodeDBErrorReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(redirectQueryRegex).WithArgs("abc123").WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/qr/abc123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

func TestDeleteDBErrorOnLookupReturns500(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectQuery(`SELECT management_token_hash FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").WillReturnError(errTest)

	w := doDelete(router, "/api/links/abc123", strings.Repeat("a", 64))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	expectations(t, mock)
}

// --- bearerToken ---

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"}, // case-insensitive no esquema
		{"BEARER abc123", "abc123"},
		{"Bearer   abc123  ", "abc123"},
		{"Basic abc123", ""},
		{"abc123", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodDelete, "/api/links/x", nil)
			if tc.header != "" {
				c.Request.Header.Set("Authorization", tc.header)
			}

			if got := bearerToken(c); got != tc.want {
				t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// --- submittedPassword ---

func TestSubmittedPasswordPrefersForm(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/abc123", strings.NewReader("password=do-form"))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request.Header.Set("X-Password", "do-header")

	if got := submittedPassword(c); got != "do-form" {
		t.Errorf("submittedPassword() = %q, want do-form", got)
	}
}

func TestSubmittedPasswordFallsBackToHeader(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/abc123", nil)
	c.Request.Header.Set("X-Password", "do-header")

	if got := submittedPassword(c); got != "do-header" {
		t.Errorf("submittedPassword() = %q, want do-header", got)
	}
}

// --- wantsHTML ---

func TestWantsHTML(t *testing.T) {
	tests := []struct {
		accept string
		want   bool
	}{
		{"text/html,application/xhtml+xml,application/xml;q=0.9", true},
		{"text/html", true},
		{"application/json", false},
		{"*/*", false}, // curl padrão: cliente de API, recebe JSON
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.accept, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/abc123", nil)
			if tc.accept != "" {
				c.Request.Header.Set("Accept", tc.accept)
			}

			if got := wantsHTML(c); got != tc.want {
				t.Errorf("wantsHTML(%q) = %v, want %v", tc.accept, got, tc.want)
			}
		})
	}
}

// --- withNonce ---

func TestWithNonceStampsInlineTags(t *testing.T) {
	html := []byte(`<html><style>body{}</style><script>x()</script></html>`)

	out := string(withNonce(html, "abc123"))

	if !strings.Contains(out, `<style nonce="abc123">`) || !strings.Contains(out, `<script nonce="abc123">`) {
		t.Errorf("tags sem nonce: %s", out)
	}
}

// Sem nonce (falha do gerador), o HTML sai intacto — melhor servir a página
// que quebrá-la; a CSP correspondente também não cita nonce.
func TestWithNonceEmptyLeavesHTMLUntouched(t *testing.T) {
	html := []byte(`<style>body{}</style>`)

	if got := string(withNonce(html, "")); got != string(html) {
		t.Errorf("withNonce(..., \"\") = %q, want inalterado", got)
	}
}

// --- contentSecurityPolicy ---

func TestContentSecurityPolicyPerRoute(t *testing.T) {
	appPolicy := contentSecurityPolicy("/", "n0nce")
	if !strings.Contains(appPolicy, "'nonce-n0nce'") {
		t.Errorf("política da app sem nonce: %q", appPolicy)
	}
	if strings.Contains(appPolicy, "unsafe-inline") {
		t.Errorf("política da app com unsafe-inline: %q", appPolicy)
	}

	// A UI do Swagger tem inline de terceiros, que não temos como carimbar.
	swaggerPolicy := contentSecurityPolicy("/swagger/index.html", "n0nce")
	if !strings.Contains(swaggerPolicy, "unsafe-inline") {
		t.Errorf("política do swagger sem unsafe-inline: %q", swaggerPolicy)
	}

	// Sem nonce, a política não pode citar 'nonce-' vazio.
	fallback := contentSecurityPolicy("/", "")
	if strings.Contains(fallback, "nonce-") {
		t.Errorf("política sem nonce citou nonce: %q", fallback)
	}
	for _, policy := range []string{appPolicy, swaggerPolicy, fallback} {
		if !strings.Contains(policy, "frame-ancestors 'none'") {
			t.Errorf("política sem frame-ancestors: %q", policy)
		}
		if !strings.Contains(policy, "form-action 'self'") {
			t.Errorf("política geral sem form-action: %q", policy)
		}
	}
}

// --- keyRateLimiter ---

// O limiter é por chave: esgotar uma não afeta as outras.
func TestKeyRateLimiterIsolatesKeys(t *testing.T) {
	l := newKeyRateLimiter(60, 2)

	for i := 0; i < 2; i++ {
		if !l.allow("a") {
			t.Fatalf("chamada %d da chave 'a' deveria passar (burst 2)", i+1)
		}
	}
	if l.allow("a") {
		t.Error("terceira chamada da chave 'a' deveria ser barrada")
	}
	if !l.allow("b") {
		t.Error("chave 'b' não pode ser afetada pelo limite de 'a'")
	}
}
