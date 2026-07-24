package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

const testPassword = "senha1234"

// testPasswordHash é o bcrypt de testPassword, gerado uma vez: com custo 12
// cada hash custa ~200ms, e recalcular por teste tornaria a suíte lenta.
var testPasswordHash = mustHashPassword(testPassword)

func mustHashPassword(pw string) string {
	hash, err := crypto.HashPassword(pw)
	if err != nil {
		panic(err)
	}
	return hash
}

const redirectQueryRegex = `SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`

// expectProtectedLink registra a busca do redirect devolvendo um link com
// senha (opcionalmente expirado/deletado).
func expectProtectedLink(mock sqlmock.Sqlmock, shortID, encrypted string, hash, expiresAt, deletedAt any) {
	mock.ExpectQuery(redirectQueryRegex).
		WithArgs(shortID).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow(shortID, encrypted, 0, expiresAt, deletedAt, hash))
}

// postForm dispara POST com corpo de formulário, como faz a tela de senha.
func postForm(router *gin.Engine, path, body string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	router.ServeHTTP(w, req)
	return w
}

// getWithHeaders dispara GET com headers/cookies arbitrários.
func getWithHeaders(router *gin.Engine, path string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	router.ServeHTTP(w, req)
	return w
}

func accessCookie(t *testing.T, value string) *http.Cookie {
	t.Helper()
	return &http.Cookie{Name: accessCookieName, Value: value}
}

// --- Criação ---

func TestAPIShortenWithPassword(t *testing.T) {
	router, mock := setupTest(t)

	// Sem consulta de dedup: link com senha nunca reaproveita existente.
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url":"https://www.example.com/secreto","password":"senha1234"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["has_password"] != true {
		t.Errorf("has_password = %v, want true", body["has_password"])
	}
	// A senha (e o hash) jamais podem sair na resposta.
	raw := w.Body.String()
	for _, leak := range []string{"senha1234", "password_hash", "$2a$", "$2b$"} {
		if strings.Contains(raw, leak) {
			t.Errorf("resposta vazou %q: %s", leak, raw)
		}
	}
	expectations(t, mock)
}

func TestAPIShortenWithoutPasswordHasPasswordFalse(t *testing.T) {
	router, mock := setupTest(t)
	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url":"https://www.example.com/publico"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if body := decodeBody(t, w); body["has_password"] != false {
		t.Errorf("has_password = %v, want false", body["has_password"])
	}
	expectations(t, mock)
}

func TestAPIShortenPasswordTooShort(t *testing.T) {
	router, mock := setupTest(t)

	w := doJSONPost(router, "/api/shorten", `{"url":"https://www.example.com/x","password":"abc"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	expectations(t, mock)
}

// --- Dedup (os dois sentidos) ---

// Sentido (a): pedir com senha nunca reaproveita — nem chega a consultar.
func TestPasswordCreationSkipsDedupLookup(t *testing.T) {
	router, mock := setupTest(t)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url":"https://www.example.com/ja-existe","password":"senha1234"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if body := decodeBody(t, w); body["existing"] != nil {
		t.Errorf("existing = %v, criação com senha nunca reaproveita link", body["existing"])
	}
	// ExpectationsWereMet falha se uma consulta de dedup tivesse ocorrido.
	expectations(t, mock)
}

// Sentido (b): a query de dedup filtra password_hash IS NULL, então quem
// encurta SEM senha nunca recebe um link protegido (que não abriria).
func TestDedupQueryIgnoresProtectedLinks(t *testing.T) {
	router, mock := setupTest(t)
	expectNoDedup(mock) // o regex exige "password_hash IS NULL" na query
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url":"https://www.example.com/ja-existe"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	expectations(t, mock)
}

// --- Redirect protegido ---

func TestProtectedRedirectWithoutCookieRendersHTML(t *testing.T) {
	router, mock := setupTest(t)
	encrypted := encrypt("https://www.example.com/destino-secreto")
	expectProtectedLink(mock, "prot01", encrypted, testPasswordHash, nil, nil)

	w := getWithHeaders(router, "/prot01", map[string]string{"Accept": "text/html,application/xhtml+xml"})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (tela de senha)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="password"`) {
		t.Error("tela de senha sem campo de senha")
	}
	// O destino NUNCA pode aparecer no HTML da tela de senha.
	if strings.Contains(body, "destino-secreto") || strings.Contains(body, encrypted) {
		t.Error("a tela de senha vazou a URL de destino")
	}
	expectations(t, mock)
}

func TestProtectedRedirectWithoutCookieReturnsJSON(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	w := doRequest(router, http.MethodGet, "/prot01") // sem Accept: text/html

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if body := decodeBody(t, w); body["error"] != "link protegido por senha" {
		t.Errorf("error = %v", body["error"])
	}
	expectations(t, mock)
}

func TestProtectedRedirectWithValidCookieRedirects(t *testing.T) {
	router, mock := setupTest(t)
	encrypted := encrypt("https://www.example.com/destino")
	expectProtectedLink(mock, "prot01", encrypted, testPasswordHash, nil, nil)
	mock.ExpectExec(`UPDATE urls SET access_count = access_count \+ 1`).
		WithArgs("prot01").WillReturnResult(sqlmock.NewResult(0, 1))

	token := testCipher.SignAccessToken("prot01", time.Now().Add(time.Hour))
	w := getWithHeaders(router, "/prot01", nil, accessCookie(t, token))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://www.example.com/destino" {
		t.Errorf("Location = %q", loc)
	}
	expectations(t, mock)
}

func TestProtectedRedirectRejectsForgedCookie(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	// Assinatura inválida: payload legítimo com HMAC trocado.
	forged := testCipher.SignAccessToken("prot01", time.Now().Add(time.Hour))
	forged = forged[:strings.LastIndex(forged, ".")] + ".00000000000000000000000000000000"

	w := getWithHeaders(router, "/prot01", nil, accessCookie(t, forged))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (cookie forjado não autoriza)", w.Code)
	}
	expectations(t, mock)
}

func TestProtectedRedirectRejectsExpiredCookie(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	expired := testCipher.SignAccessToken("prot01", time.Now().Add(-time.Minute))
	w := getWithHeaders(router, "/prot01", nil, accessCookie(t, expired))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (cookie expirado não autoriza)", w.Code)
	}
	expectations(t, mock)
}

// Cookie legítimo de OUTRO link não serve: o short_id vai dentro do payload
// assinado.
func TestAccessCookieIsBoundToShortID(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	other := testCipher.SignAccessToken("outro1", time.Now().Add(time.Hour))
	w := getWithHeaders(router, "/prot01", nil, accessCookie(t, other))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (cookie de outro link não autoriza)", w.Code)
	}
	expectations(t, mock)
}

// --- Submissão da senha ---

func TestPasswordSubmitCorrectIssuesCookieAndRedirects(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)
	mock.ExpectExec(`UPDATE urls SET access_count = access_count \+ 1`).
		WithArgs("prot01").WillReturnResult(sqlmock.NewResult(0, 1))

	w := postForm(router, "/prot01", "password="+testPassword, nil)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://www.example.com/destino" {
		t.Errorf("Location = %q", loc)
	}

	var cookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == accessCookieName {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatal("cookie de acesso não emitido")
	}
	if !cookie.HttpOnly {
		t.Error("cookie de acesso deve ser HttpOnly")
	}
	if cookie.Path != "/prot01" {
		t.Errorf("cookie.Path = %q, want /prot01", cookie.Path)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie.SameSite = %v, want Lax", cookie.SameSite)
	}
	if err := testCipher.VerifyAccessToken(cookie.Value, "prot01", time.Now()); err != nil {
		t.Errorf("cookie emitido não valida: %v", err)
	}
	expectations(t, mock)
}

func TestPasswordSubmitViaHeader(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)
	mock.ExpectExec(`UPDATE urls SET access_count = access_count \+ 1`).
		WithArgs("prot01").WillReturnResult(sqlmock.NewResult(0, 1))

	w := postForm(router, "/prot01", "", map[string]string{"X-Password": testPassword})

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	expectations(t, mock)
}

func TestPasswordSubmitWrongDoesNotAuthorize(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	w := postForm(router, "/prot01", "password=errada123", nil)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == accessCookieName && ck.Value != "" {
			t.Error("senha errada não pode emitir cookie de acesso")
		}
	}
	if strings.Contains(w.Body.String(), "example.com/destino") {
		t.Error("resposta de senha errada vazou o destino")
	}
	expectations(t, mock)
}

func TestPasswordSubmitWrongShowsErrorOnHTML(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	w := postForm(router, "/prot01", "password=errada123", map[string]string{"Accept": "text/html"})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), errWrongPassword) {
		t.Errorf("tela reexibida sem mensagem de erro: %s", w.Body.String())
	}
	expectations(t, mock)
}

// --- Anti-força-bruta ---

func TestPasswordAttemptsAreRateLimitedByShortID(t *testing.T) {
	router, mock := setupTest(t)

	// O limiter roda ANTES do handler, então basta um link inexistente para
	// consumir as tentativas: cada POST responde 404 sem verificar senha.
	// Isso é deliberado — verificar bcrypt (custo 12, ~200ms e muito mais sob
	// -race) tornaria o teste lento o bastante para o limiter RECARREGAR
	// tokens no meio do laço, e a asserção viraria dependente de tempo.
	for i := 0; i < passwordRateBurst; i++ {
		mock.ExpectQuery(redirectQueryRegex).WithArgs("prot01").
			WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}))
	}

	for i := 0; i < passwordRateBurst; i++ {
		if w := postForm(router, "/prot01", "password=errada123", nil); w.Code != http.StatusNotFound {
			t.Fatalf("tentativa %d: status = %d, want 404", i+1, w.Code)
		}
	}

	// A tentativa seguinte é barrada pelo limiter — sem sequer consultar o
	// banco (nenhuma expectativa adicional foi registrada).
	w := postForm(router, "/prot01", "password=errada123", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 após esgotar as tentativas", w.Code)
	}
	expectations(t, mock)
}

// O limiter de senha é independente do de criação: esgotar as tentativas de
// um link não impede criar links nem abrir OUTRO link protegido.
func TestPasswordRateLimitIsPerLink(t *testing.T) {
	router, mock := setupTest(t)

	for i := 0; i < passwordRateBurst+1; i++ {
		if i < passwordRateBurst {
			mock.ExpectQuery(redirectQueryRegex).WithArgs("prot01").
				WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}))
		}
		postForm(router, "/prot01", "password=errada123", nil)
	}

	mock.ExpectQuery(redirectQueryRegex).WithArgs("outro1").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}))

	if w := postForm(router, "/outro1", "password=errada123", nil); w.Code == http.StatusTooManyRequests {
		t.Error("o limite de um link não pode afetar outro")
	}
	expectations(t, mock)
}

// --- Precedência: expiração/delete antes da senha ---

func TestExpiredProtectedLinkReturnsGoneNotPasswordPage(t *testing.T) {
	router, mock := setupTest(t)
	past := time.Now().Add(-time.Hour)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, past, nil)

	w := getWithHeaders(router, "/prot01", map[string]string{"Accept": "text/html"})

	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", w.Code)
	}
	if strings.Contains(w.Body.String(), `name="password"`) {
		t.Error("link expirado não pode exibir a tela de senha")
	}
	expectations(t, mock)
}

func TestDeletedProtectedLinkReturnsGone(t *testing.T) {
	router, mock := setupTest(t)
	deleted := time.Now().Add(-time.Minute)
	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, deleted)

	w := getWithHeaders(router, "/prot01", map[string]string{"Accept": "text/html"})

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", w.Code)
	}
	expectations(t, mock)
}

// POST de senha em link sem senha não tem o que autenticar.
func TestPasswordSubmitOnPublicLinkIs404(t *testing.T) {
	router, mock := setupTest(t)
	expectProtectedLink(mock, "publi1", encrypt("https://www.example.com/publico"), nil, nil, nil)

	w := postForm(router, "/publi1", "password="+testPassword, nil)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	expectations(t, mock)
}

// A tela de senha não pode gerar clique: o analytics só registra redirect
// concluído.
// countingRecorder conta os cliques registrados.
type countingRecorder struct{ count int }

func (r *countingRecorder) Record(analytics.Click) { r.count++ }

func TestPasswordPageDoesNotRecordClick(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { mockDB.Close() })

	rec := &countingRecorder{}
	server := New(storage.NewPostgres(mockDB), testCipher, rec, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	router := server.Router()

	expectProtectedLink(mock, "prot01", encrypt("https://www.example.com/destino"), testPasswordHash, nil, nil)

	if w := getWithHeaders(router, "/prot01", map[string]string{"Accept": "text/html"}); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if rec.count != 0 {
		t.Errorf("cliques registrados = %d, want 0 na exibição da tela de senha", rec.count)
	}
	expectations(t, mock)
}
