package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

// Testes de caracterização: capturam o comportamento ATUAL dos 4 endpoints,
// com o banco substituído por go-sqlmock por trás do Repository.

const testKey = "0123456789abcdef0123456789abcdef"

var errTest = errors.New("simulated database error")

var testCipher, _ = crypto.New([]byte(testKey))

// encrypt mantém a assinatura usada nas asserções dos testes de
// caracterização originais.
func encrypt(plainText string) string {
	encrypted, err := testCipher.Encrypt(plainText)
	if err != nil {
		panic(err)
	}
	return encrypted
}

// noopRecorder descarta eventos: os testes de HTTP não exercem o registro
// assíncrono (coberto em internal/analytics), evitando inserts no sqlmock.
type noopRecorder struct{}

func (noopRecorder) Record(analytics.Click) {}

func setupTest(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	return setupTestFull(t, true, nil)
}

func setupTestSwagger(t *testing.T, swaggerEnabled bool) (*gin.Engine, sqlmock.Sqlmock) {
	return setupTestFull(t, swaggerEnabled, nil)
}

func setupTestChecker(t *testing.T, checker URLChecker) (*gin.Engine, sqlmock.Sqlmock) {
	return setupTestFull(t, true, checker)
}

func setupTestFull(t *testing.T, swaggerEnabled bool, checker URLChecker) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { mockDB.Close() })

	server := New(storage.NewPostgres(mockDB), testCipher, noopRecorder{}, checker,
		slog.New(slog.NewTextHandler(io.Discard, nil)), Options{SwaggerEnabled: swaggerEnabled})

	return server.Router(), mock
}

// fakeChecker implementa URLChecker para os testes de integração.
type fakeChecker struct {
	malicious bool
	err       error
}

func (f fakeChecker) Malicious(_ context.Context, _ string) (bool, error) {
	return f.malicious, f.err
}

func doRequest(router *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	router.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body %q: %v", w.Body.String(), err)
	}
	return body
}

func expectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// dedupQueryRegex casa a consulta de dedup inteira, incluindo o filtro que
// ignora registros expirados (dedup não pode devolver link morto).
const dedupQueryRegex = `SELECT short_id, original_url, created_at, access_count FROM urls WHERE url_hash = \$1 AND deleted_at IS NULL AND password_hash IS NULL AND \(expires_at IS NULL OR expires_at > now\(\)\)`

// expectNoDedup registra a consulta de dedup por url_hash sem resultado.
func expectNoDedup(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(dedupQueryRegex).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}))
}

// --- GET /shorten ---

func TestShortenMissingURL(t *testing.T) {
	router, mock := setupTest(t)

	w := doRequest(router, http.MethodGet, "/shorten")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "URL parameter is missing" {
		t.Errorf("error = %q, want %q", body["error"], "URL parameter is missing")
	}
	expectations(t, mock)
}

func TestShortenInvalidURL(t *testing.T) {
	router, mock := setupTest(t)

	w := doRequest(router, http.MethodGet, "/shorten?url=ftp://example.com")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "URL must be a valid http:// or https:// URL" {
		t.Errorf("error = %q, want %q", body["error"], "URL must be a valid http:// or https:// URL")
	}
	expectations(t, mock)
}

// --- POST /api/shorten ---

func doJSONPost(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

func TestAPIShortenSuccess(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.destino.com/pagina"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	shortID, _ := body["short_id"].(string)
	if !regexp.MustCompile(`^[a-zA-Z0-9]{6}$`).MatchString(shortID) {
		t.Errorf("short_id = %q, want 6 alfanuméricos", shortID)
	}
	if body["original_url"] != "https://www.destino.com/pagina" {
		t.Errorf("original_url = %q", body["original_url"])
	}
	if body["short_url"] != "http://example.com/"+shortID {
		t.Errorf("short_url = %q, want host + short_id", body["short_url"])
	}
	if _, ok := body["created_at"]; !ok {
		t.Error("response missing created_at")
	}
	// Token de gerenciamento devolvido UMA vez na criação (64 hex).
	mt, _ := body["management_token"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(mt) {
		t.Errorf("management_token = %q, want 64 hex chars", mt)
	}
	expectations(t, mock)
}

func TestAPIShortenInvalidBody(t *testing.T) {
	router, mock := setupTest(t)

	for _, body := range []string{``, `{}`, `{"url": ""}`, `nao é json`} {
		w := doJSONPost(router, "/api/shorten", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, w.Code)
		}
	}
	expectations(t, mock)
}

func TestAPIShortenInvalidURL(t *testing.T) {
	router, mock := setupTest(t)

	for _, u := range []string{"ftp://x.com", "http://", "somentetexto", "https:///caminho"} {
		w := doJSONPost(router, "/api/shorten", `{"url": "`+u+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("url %q: status = %d, want 400", u, w.Code)
		}
		body := decodeBody(t, w)
		if body["error"] != "URL must be a valid http:// or https:// URL" {
			t.Errorf("url %q: error = %q", u, body["error"])
		}
	}
	expectations(t, mock)
}

func TestAPIShortenRejectsSelfReference(t *testing.T) {
	router, mock := setupTest(t)

	// httptest.NewRequest usa example.com como host da requisição.
	w := doJSONPost(router, "/api/shorten", `{"url": "http://example.com/abc123"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "URL must not point to this service" {
		t.Errorf("error = %q, want self-reference rejection", body["error"])
	}
	expectations(t, mock)
}

func TestAPIShortenWithCustomAlias(t *testing.T) {
	router, mock := setupTest(t)

	// Alias explícito não passa por dedup; grava direto com o alias.
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "custom_alias": "meu-link_1"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["short_id"] != "meu-link_1" {
		t.Errorf("short_id = %q, want %q", body["short_id"], "meu-link_1")
	}
	if body["short_url"] != "http://example.com/meu-link_1" {
		t.Errorf("short_url = %q, want alias", body["short_url"])
	}
	expectations(t, mock)
}

func TestAPIShortenAliasInvalidFormat(t *testing.T) {
	router, mock := setupTest(t)

	for _, alias := range []string{"ab", "com espaço", "tem/barra", strings.Repeat("x", 31)} {
		body := `{"url": "https://www.example.com", "custom_alias": "` + alias + `"}`
		w := doJSONPost(router, "/api/shorten", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("alias %q: status = %d, want 400", alias, w.Code)
		}
	}
	expectations(t, mock) // nenhuma query esperada
}

func TestAPIShortenAliasReserved(t *testing.T) {
	router, mock := setupTest(t)

	for _, alias := range []string{"api", "health", "metrics", "Stats"} {
		body := `{"url": "https://www.example.com", "custom_alias": "` + alias + `"}`
		w := doJSONPost(router, "/api/shorten", body)
		if w.Code != http.StatusConflict {
			t.Errorf("alias %q: status = %d, want 409", alias, w.Code)
		}
	}
	expectations(t, mock)
}

func TestAPIShortenAliasCollision(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectExec(`INSERT INTO urls`).WillReturnError(storage.ErrDuplicate)

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "custom_alias": "tomado"}`)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["error"] != "custom_alias already in use" {
		t.Errorf("error = %q", body["error"])
	}
	expectations(t, mock)
}

// Alias com mais de 6 caracteres (o antigo limite de short_id): deve ser
// aceito agora que a coluna é VARCHAR(30).
func TestAPIShortenLongAliasSucceeds(t *testing.T) {
	router, mock := setupTest(t)

	const alias = "meu-alias-bem-descritivo-123" // 28 chars, > 6
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "custom_alias": "`+alias+`"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["short_id"] != alias {
		t.Errorf("short_id = %q, want %q", body["short_id"], alias)
	}
	expectations(t, mock)
}

// Defesa em profundidade: se o insert falhar por truncamento (validação e
// schema divergentes), o cliente recebe 400, não 500 genérico.
func TestAPIShortenAliasTooLongForColumn(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectExec(`INSERT INTO urls`).WillReturnError(storage.ErrValueTooLong)

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "custom_alias": "alias-que-nao-cabe"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["error"] != "custom_alias is too long" {
		t.Errorf("error = %q", body["error"])
	}
	expectations(t, mock)
}

func TestAPIShortenBlocksMaliciousURL(t *testing.T) {
	router, mock := setupTestChecker(t, fakeChecker{malicious: true})

	// URL maliciosa: nenhuma query ao banco (bloqueia antes do dedup/insert).
	w := doJSONPost(router, "/api/shorten", `{"url": "http://malware.test"}`)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	want := "URL bloqueada: identificada como potencialmente maliciosa (phishing/malware)"
	if body["error"] != want {
		t.Errorf("error = %q, want %q", body["error"], want)
	}
	expectations(t, mock)
}

func TestAPIShortenFailOpenOnCheckerError(t *testing.T) {
	router, mock := setupTestChecker(t, fakeChecker{err: errTest})

	// Erro na verificação → fail-open: a criação prossegue normalmente.
	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (fail-open); body = %s", w.Code, w.Body.String())
	}
	expectations(t, mock)
}

func TestAPIShortenCleanURLPasses(t *testing.T) {
	router, mock := setupTestChecker(t, fakeChecker{malicious: false})

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	expectations(t, mock)
}

func TestAPIShortenDedupReturnsExistingShortID(t *testing.T) {
	router, mock := setupTest(t)

	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE url_hash = \$1`).
		WithArgs(testCipher.Hash("https://www.destino.com/pagina")).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("jaexis", encrypt("https://www.destino.com/pagina"), createdAt, 5))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.destino.com/pagina"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for existing URL; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["existing"] != true {
		t.Errorf("existing = %v, want true", body["existing"])
	}
	if body["short_id"] != "jaexis" {
		t.Errorf("short_id = %q, want reused %q", body["short_id"], "jaexis")
	}
	if body["short_url"] != "http://example.com/jaexis" {
		t.Errorf("short_url = %q", body["short_url"])
	}
	// Dedup NÃO devolve management_token — só o criador original o tem.
	if _, ok := body["management_token"]; ok {
		t.Error("resposta de dedup não deve conter management_token")
	}
	expectations(t, mock)
}

// (a) O único match está expirado: o filtro da query o exclui, o dedup não
// encontra nada e um link novo é criado normalmente.
func TestAPIShortenDedupIgnoresExpiredLink(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock) // filtro de expiração exclui o registro expirado
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com/expirada"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (novo link, não o expirado); body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["existing"] != nil {
		t.Errorf("existing = %v, want ausente em criação nova", body["existing"])
	}
	shortID, _ := body["short_id"].(string)
	if !regexp.MustCompile(`^[a-zA-Z0-9]{6}$`).MatchString(shortID) {
		t.Errorf("short_id = %q, want novo id de 6 alfanuméricos", shortID)
	}
	expectations(t, mock)
}

// (b) Match com expiração no futuro continua sendo reaproveitado.
func TestAPIShortenDedupReusesValidLink(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(dedupQueryRegex).
		WithArgs(testCipher.Hash("https://www.example.com/valida")).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("valido", encrypt("https://www.example.com/valida"), time.Now(), 2))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com/valida"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["existing"] != true || body["short_id"] != "valido" {
		t.Errorf("existing = %v, short_id = %v; want reaproveitamento de %q", body["existing"], body["short_id"], "valido")
	}
	expectations(t, mock)
}

// (c) Link permanente (expires_at NULL) segue sendo reaproveitado.
func TestAPIShortenDedupReusesPermanentLink(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(dedupQueryRegex).
		WithArgs(testCipher.Hash("https://www.example.com/permanente")).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("eterno", encrypt("https://www.example.com/permanente"), time.Now(), 9))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com/permanente"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["existing"] != true || body["short_id"] != "eterno" {
		t.Errorf("existing = %v, short_id = %v; want reaproveitamento de %q", body["existing"], body["short_id"], "eterno")
	}
	expectations(t, mock)
}

func TestShortenDedupOnLegacyGET(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE url_hash = \$1`).
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("jaexis", encrypt("https://www.example.com"), time.Now(), 1))

	w := doRequest(router, http.MethodGet, "/shorten?url=https://www.example.com")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["existing"] != true {
		t.Errorf("existing = %v, want true", body["existing"])
	}
	if body["short_url"] != "http://example.com/jaexis" {
		t.Errorf("short_url = %q, want reused short_id", body["short_url"])
	}
	expectations(t, mock)
}

func TestShortenSuccess(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := doRequest(router, http.MethodGet, "/shorten?url=https://www.example.com")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["original_url"] != "https://www.example.com" {
		t.Errorf("original_url = %q, want %q", body["original_url"], "https://www.example.com")
	}
	shortURL, _ := body["short_url"].(string)
	if !regexp.MustCompile(`^http://example\.com/[a-zA-Z0-9]{6}$`).MatchString(shortURL) {
		t.Errorf("short_url = %q, want http://example.com/<6 alfanuméricos>", shortURL)
	}
	if _, ok := body["created_at"]; !ok {
		t.Error("response missing created_at")
	}
	expectations(t, mock)
}

func TestShortenInsertFailure(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).
		WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/shorten?url=https://www.example.com")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "Failed to shorten URL" {
		t.Errorf("error = %q, want %q", body["error"], "Failed to shorten URL")
	}
	expectations(t, mock)
}

func TestShortenRetriesOnShortIDCollision(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnError(storage.ErrDuplicate)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doRequest(router, http.MethodGet, "/shorten?url=https://www.example.com")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 after collision retry; body = %s", w.Code, w.Body.String())
	}
	expectations(t, mock)
}

func TestShortenFailsAfterExhaustingCollisionRetries(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	for i := 0; i < 3; i++ {
		mock.ExpectExec(`INSERT INTO urls`).WillReturnError(storage.ErrDuplicate)
	}

	w := doRequest(router, http.MethodGet, "/shorten?url=https://www.example.com")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 after 3 collisions", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "Failed to shorten URL" {
		t.Errorf("error = %q", body["error"])
	}
	expectations(t, mock)
}

func TestShortenRateLimit(t *testing.T) {
	router, mock := setupTest(t)

	// Requisições sem o parâmetro url não tocam o banco, mas contam para o
	// limite. O burst é 10: as 10 primeiras passam (400), a 11ª leva 429.
	for i := 0; i < 10; i++ {
		if w := doRequest(router, http.MethodGet, "/shorten"); w.Code != http.StatusBadRequest {
			t.Fatalf("request %d: status = %d, want 400", i+1, w.Code)
		}
	}

	w := doRequest(router, http.MethodGet, "/shorten")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 after burst", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "rate limit exceeded, try again later" {
		t.Errorf("error = %q", body["error"])
	}
	expectations(t, mock)
}

// --- GET / (landing page) ---

func TestLandingPage(t *testing.T) {
	router, mock := setupTest(t)

	w := doRequest(router, http.MethodGet, "/")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "small-links") {
		t.Error("corpo não contém o título esperado")
	}
	expectations(t, mock)
}

// O metricsMiddleware deve rotular a landing como route="/" (rota registrada),
// não cair no bucket "unmatched".
func TestLandingMetricsRouteLabel(t *testing.T) {
	router, mock := setupTest(t)

	doRequest(router, http.MethodGet, "/")
	w := doRequest(router, http.MethodGet, "/metrics")

	if !strings.Contains(w.Body.String(), `route="/"`) {
		t.Error("métrica de latência não registrou route=\"/\" para a landing")
	}
	expectations(t, mock)
}

// --- GET /swagger ---

func TestSwaggerUIServedWhenEnabled(t *testing.T) {
	router, mock := setupTestSwagger(t, true)

	w := doRequest(router, http.MethodGet, "/swagger/index.html")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (UI do Swagger)", w.Code)
	}
	expectations(t, mock)
}

func TestSwaggerDisabledReturns404(t *testing.T) {
	router, mock := setupTestSwagger(t, false)

	w := doRequest(router, http.MethodGet, "/swagger/index.html")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 quando o Swagger está desabilitado", w.Code)
	}
	expectations(t, mock)
}

// --- GET /metrics ---

func TestMetricsEndpoint(t *testing.T) {
	router, mock := setupTest(t)

	w := doRequest(router, http.MethodGet, "/metrics")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, name := range []string{
		"smalllinks_redirects_total",
		"smalllinks_shortens_total",
		"smalllinks_rate_limited_total",
	} {
		if !strings.Contains(w.Body.String(), name) {
			t.Errorf("/metrics não expõe %q", name)
		}
	}
	expectations(t, mock)
}

// --- GET /qr/:shortId ---

func TestQRCodeSuccess(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("abc123", encrypt("https://www.example.com"), 0, nil, nil, nil))

	w := doRequest(router, http.MethodGet, "/qr/abc123")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	// PNG começa com a assinatura \x89PNG.
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG")) {
		t.Error("corpo não começa com a assinatura PNG")
	}
	expectations(t, mock)
}

func TestQRCodeNotFound(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("naoexi").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}))

	w := doRequest(router, http.MethodGet, "/qr/naoexi")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	expectations(t, mock)
}

// --- DELETE /api/links/:shortId ---

func doDelete(router *gin.Engine, path, bearer string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	router.ServeHTTP(w, req)
	return w
}

const validToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func expectManagementHash(mock sqlmock.Sqlmock, shortID string, hash interface{}) {
	rows := sqlmock.NewRows([]string{"management_token_hash"})
	if hash != nil {
		rows.AddRow(hash)
	} else {
		rows.AddRow(nil)
	}
	mock.ExpectQuery(`SELECT management_token_hash FROM urls WHERE short_id = \$1`).
		WithArgs(shortID).WillReturnRows(rows)
}

func TestDeleteValidToken(t *testing.T) {
	router, mock := setupTest(t)

	expectManagementHash(mock, "abc123", crypto.TokenSHA256(validToken))
	mock.ExpectExec(`UPDATE urls SET deleted_at = now\(\) WHERE short_id = \$1 AND deleted_at IS NULL`).
		WithArgs("abc123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doDelete(router, "/api/links/abc123", validToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", w.Code, w.Body.String())
	}
	expectations(t, mock)
}

// Token errado para link existente → 403; nenhum UPDATE (não deleta).
func TestDeleteWrongTokenExistingLink(t *testing.T) {
	router, mock := setupTest(t)

	expectManagementHash(mock, "abc123", crypto.TokenSHA256("o-token-certo"))

	w := doDelete(router, "/api/links/abc123", "token-errado")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	expectations(t, mock)
}

// CRÍTICO: short_id inexistente → 403 uniforme (NÃO 404), sem vazar existência.
func TestDeleteNonexistentIsUniform403(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT management_token_hash FROM urls WHERE short_id = \$1`).
		WithArgs("naoexi").
		WillReturnRows(sqlmock.NewRows([]string{"management_token_hash"}))

	w := doDelete(router, "/api/links/naoexi", validToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (uniforme, sem vazar existência)", w.Code)
	}
	expectations(t, mock)
}

func TestDeleteMissingTokenIs403(t *testing.T) {
	router, mock := setupTest(t)
	// Sem Authorization: 403 sem sequer consultar o banco.
	w := doDelete(router, "/api/links/abc123", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	expectations(t, mock)
}

// Link antigo (management_token_hash NULL) é não-gerenciável → 403.
func TestDeleteOldLinkNullHashIs403(t *testing.T) {
	router, mock := setupTest(t)

	expectManagementHash(mock, "antigo", nil)

	w := doDelete(router, "/api/links/antigo", validToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	expectations(t, mock)
}

// Após o delete, o redirect do link responde 410 Gone.
func TestRedirectDeletedReturnsGone(t *testing.T) {
	router, mock := setupTest(t)

	deleted := time.Now().Add(-time.Hour)
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("morto").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("morto", encrypt("https://www.example.com"), 5, nil, deleted, nil))

	w := doRequest(router, http.MethodGet, "/morto")
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["error"] != "Short URL has been deleted" {
		t.Errorf("error = %q", body["error"])
	}
	expectations(t, mock)
}

// QR de link deletado → 410.
func TestQRCodeDeletedReturnsGone(t *testing.T) {
	router, mock := setupTest(t)

	deleted := time.Now().Add(-time.Hour)
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("morto").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("morto", encrypt("https://www.example.com"), 0, nil, deleted, nil))

	w := doRequest(router, http.MethodGet, "/qr/morto")
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", w.Code)
	}
	expectations(t, mock)
}

// Dedup ignora deletados: a query filtra deleted_at IS NULL (o regex de
// expectNoDedup o exige), então reencurtar a mesma URL cria um link NOVO.
func TestAPIShortenDedupIgnoresDeletedLink(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com/deletada"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (novo link); body = %s", w.Code, w.Body.String())
	}
	expectations(t, mock)
}

// Um short_id deletado NUNCA é reciclado como alias novo: o registro
// permanece (soft delete) e a constraint UNIQUE bloqueia → 409.
func TestAliasDoesNotRecycleDeletedShortID(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectExec(`INSERT INTO urls`).WillReturnError(storage.ErrDuplicate)

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "custom_alias": "deletado"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (short_id deletado não recicla)", w.Code)
	}
	expectations(t, mock)
}

// --- GET /:shortId ---

func TestRedirectSuccess(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com/destino")
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("abc123", encrypted, 7, nil, nil, nil))
	mock.ExpectExec(`UPDATE urls SET access_count = access_count \+ 1 WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doRequest(router, http.MethodGet, "/abc123")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://www.example.com/destino" {
		t.Errorf("Location = %q, want %q", loc, "https://www.example.com/destino")
	}
	expectations(t, mock)
}

func TestRedirectNotFound(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("naoexi").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}))

	w := doRequest(router, http.MethodGet, "/naoexi")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "Short URL not found" {
		t.Errorf("error = %q, want %q", body["error"], "Short URL not found")
	}
	expectations(t, mock)
}

func TestRedirectExpiredReturnsGone(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com")
	past := time.Now().Add(-1 * time.Hour)
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("expira").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("expira", encrypted, 3, past, nil, nil))

	w := doRequest(router, http.MethodGet, "/expira")

	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["error"] != "Short URL has expired" {
		t.Errorf("error = %q", body["error"])
	}
	// Expirado não deve incrementar access_count (nenhum UPDATE esperado).
	expectations(t, mock)
}

func TestRedirectNotYetExpired(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com/futuro")
	future := time.Now().Add(24 * time.Hour)
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls WHERE short_id = \$1`).
		WithArgs("valido").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("valido", encrypted, 0, future, nil, nil))
	mock.ExpectExec(`UPDATE urls SET access_count`).
		WithArgs("valido").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doRequest(router, http.MethodGet, "/valido")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://www.example.com/futuro" {
		t.Errorf("Location = %q", loc)
	}
	expectations(t, mock)
}

func TestAPIShortenWithExpiration(t *testing.T) {
	router, mock := setupTest(t)

	expectNoDedup(mock)
	mock.ExpectExec(`INSERT INTO urls`).WillReturnResult(sqlmock.NewResult(1, 1))

	w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "expires_in_days": 7}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if _, ok := body["expires_at"]; !ok {
		t.Error("resposta deveria conter expires_at")
	}
	expectations(t, mock)
}

func TestAPIShortenInvalidExpiration(t *testing.T) {
	router, mock := setupTest(t)

	for _, v := range []string{"0", "-5"} {
		w := doJSONPost(router, "/api/shorten", `{"url": "https://www.example.com", "expires_in_days": `+v+`}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expires_in_days=%s: status = %d, want 400", v, w.Code)
		}
	}
	expectations(t, mock) // nenhuma query esperada
}

// Caracteriza: falha ao incrementar access_count NÃO impede o redirect.
func TestRedirectUpdateFailureStillRedirects(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com")
	mock.ExpectQuery(`SELECT short_id, original_url, access_count, expires_at, deleted_at, password_hash FROM urls`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count", "expires_at", "deleted_at", "password_hash"}).
			AddRow("abc123", encrypted, 0, nil, nil, nil))
	mock.ExpectExec(`UPDATE urls SET access_count`).
		WithArgs("abc123").
		WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/abc123")

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 mesmo com falha no UPDATE", w.Code)
	}
	expectations(t, mock)
}

// --- GET /stats/:shortId ---

// expectClickStats registra as cinco queries de ClickStats na ordem em que
// o repositório as executa: total, cliques/dia, top referrers, top países e
// dispositivos. Os regex exigem o filtro NOT is_bot — bots ficam fora de
// todas as agregações.
func expectClickStats(mock sqlmock.Sqlmock, shortID string, total int, days []storage.DailyClicks, refs []storage.ReferrerCount, countries []storage.CountryCount, devices []storage.DeviceCount) {
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM click_events WHERE short_id = \$1 AND NOT is_bot`).
		WithArgs(shortID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(total))

	dayRows := sqlmock.NewRows([]string{"day", "count"})
	for _, d := range days {
		parsed, _ := time.Parse("2006-01-02", d.Day)
		dayRows.AddRow(parsed, d.Count)
	}
	mock.ExpectQuery(`SELECT date_trunc\('day', occurred_at\) AS day, COUNT\(\*\)[\s\S]*NOT is_bot`).
		WithArgs(shortID).
		WillReturnRows(dayRows)

	refRows := sqlmock.NewRows([]string{"referrer", "n"})
	for _, r := range refs {
		refRows.AddRow(r.Referrer, r.Count)
	}
	mock.ExpectQuery(`SELECT referrer, COUNT\(\*\) AS n[\s\S]*NOT is_bot`).
		WithArgs(shortID).
		WillReturnRows(refRows)

	countryRows := sqlmock.NewRows([]string{"country", "n"})
	for _, c := range countries {
		countryRows.AddRow(c.Country, c.Count)
	}
	mock.ExpectQuery(`SELECT COALESCE\(country, 'unknown'\) AS country, COUNT\(\*\) AS n[\s\S]*NOT is_bot`).
		WithArgs(shortID).
		WillReturnRows(countryRows)

	deviceRows := sqlmock.NewRows([]string{"device", "n"})
	for _, d := range devices {
		deviceRows.AddRow(d.Device, d.Count)
	}
	mock.ExpectQuery(`SELECT COALESCE\(device, 'unknown'\) AS device, COUNT\(\*\) AS n[\s\S]*NOT is_bot`).
		WithArgs(shortID).
		WillReturnRows(deviceRows)
}

func TestStatsSuccess(t *testing.T) {
	router, mock := setupTest(t)

	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	encrypted := encrypt("https://www.example.com")
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("abc123", encrypted, createdAt, 42))
	expectClickStats(mock, "abc123",
		42,
		[]storage.DailyClicks{{Day: "2026-01-01", Count: 30}, {Day: "2026-01-02", Count: 12}},
		[]storage.ReferrerCount{{Referrer: "https://news.example", Count: 20}, {Referrer: "https://x.example", Count: 8}},
		[]storage.CountryCount{{Country: "BR", Count: 25}, {Country: "US", Count: 10}},
		[]storage.DeviceCount{{Device: "mobile", Count: 30}, {Device: "desktop", Count: 12}},
	)

	w := doRequest(router, http.MethodGet, "/stats/abc123")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["short_id"] != "abc123" {
		t.Errorf("short_id = %q, want %q", body["short_id"], "abc123")
	}
	if body["original_url"] != "https://www.example.com" {
		t.Errorf("original_url = %q, want %q", body["original_url"], "https://www.example.com")
	}
	if body["access_count"] != float64(42) {
		t.Errorf("access_count = %v, want 42", body["access_count"])
	}
	if _, ok := body["created_at"]; !ok {
		t.Error("response missing created_at")
	}

	// Campos novos de analytics.
	if body["total_clicks"] != float64(42) {
		t.Errorf("total_clicks = %v, want 42", body["total_clicks"])
	}
	perDay, ok := body["clicks_per_day"].([]any)
	if !ok || len(perDay) != 2 {
		t.Fatalf("clicks_per_day = %v, want 2 entradas", body["clicks_per_day"])
	}
	first := perDay[0].(map[string]any)
	if first["day"] != "2026-01-01" || first["count"] != float64(30) {
		t.Errorf("clicks_per_day[0] = %v, want {2026-01-01, 30}", first)
	}
	refs, ok := body["top_referrers"].([]any)
	if !ok || len(refs) != 2 {
		t.Fatalf("top_referrers = %v, want 2 entradas", body["top_referrers"])
	}
	topRef := refs[0].(map[string]any)
	if topRef["referrer"] != "https://news.example" || topRef["count"] != float64(20) {
		t.Errorf("top_referrers[0] = %v, want {news.example, 20}", topRef)
	}

	// Novos campos de geo/dispositivo.
	countries, ok := body["top_countries"].([]any)
	if !ok || len(countries) != 2 {
		t.Fatalf("top_countries = %v, want 2 entradas", body["top_countries"])
	}
	topCountry := countries[0].(map[string]any)
	if topCountry["country"] != "BR" || topCountry["count"] != float64(25) {
		t.Errorf("top_countries[0] = %v, want {BR, 25}", topCountry)
	}
	devices, ok := body["devices"].([]any)
	if !ok || len(devices) != 2 {
		t.Fatalf("devices = %v, want 2 entradas", body["devices"])
	}
	topDevice := devices[0].(map[string]any)
	if topDevice["device"] != "mobile" || topDevice["count"] != float64(30) {
		t.Errorf("devices[0] = %v, want {mobile, 30}", topDevice)
	}
	expectations(t, mock)
}

func TestStatsEmptyAnalytics(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com")
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("abc123", encrypted, time.Now(), 0))
	expectClickStats(mock, "abc123", 0, nil, nil, nil, nil)

	w := doRequest(router, http.MethodGet, "/stats/abc123")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	// Fatias vazias devem serializar como [] (não null) por compatibilidade.
	if got := strings.Count(w.Body.String(), "null"); got != 0 {
		t.Errorf("body contém null: %s", w.Body.String())
	}
	body := decodeBody(t, w)
	if arr, ok := body["clicks_per_day"].([]any); !ok || len(arr) != 0 {
		t.Errorf("clicks_per_day = %v, want []", body["clicks_per_day"])
	}
	expectations(t, mock)
}

func TestStatsNotFound(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("naoexi").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}))

	w := doRequest(router, http.MethodGet, "/stats/naoexi")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "Short URL not found" {
		t.Errorf("error = %q, want %q", body["error"], "Short URL not found")
	}
	expectations(t, mock)
}

// --- GET /health ---

func TestHealthSuccess(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM urls`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	w := doRequest(router, http.MethodGet, "/health")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["status"] != "healthy" {
		t.Errorf("status = %q, want %q", body["status"], "healthy")
	}
	if body["total_urls"] != float64(3) {
		t.Errorf("total_urls = %v, want 3", body["total_urls"])
	}
	if _, ok := body["timestamp"]; !ok {
		t.Error("response missing timestamp")
	}
	expectations(t, mock)
}

func TestHealthDBFailure(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM urls`).WillReturnError(errTest)

	w := doRequest(router, http.MethodGet, "/health")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := decodeBody(t, w)
	if body["status"] != "unhealthy" {
		t.Errorf("status = %q, want %q", body["status"], "unhealthy")
	}
	expectations(t, mock)
}

// --- CORS ---

func TestCORSPreflight(t *testing.T) {
	router, mock := setupTest(t)

	w := doRequestWithOrigin(router, http.MethodOptions, "/health", "http://example.com")

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	// Sem CORS_ALLOWED_ORIGINS, a própria origem da aplicação (o Host da
	// requisição, "example.com") é a única autorizada.
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "http://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", origin, "http://example.com")
	}
	expectations(t, mock)
}

// --- Resolução do IP do cliente (TRUSTED_PLATFORM) ---

// clientIPRouter monta um router com o mesmo esquema de confiança do Server e
// uma rota que devolve o IP resolvido, permitindo asserção direta.
func clientIPRouter(t *testing.T, trustedPlatform string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mockDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { mockDB.Close() })

	server := New(storage.NewPostgres(mockDB), testCipher, noopRecorder{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), Options{TrustedPlatform: trustedPlatform})

	router := server.Router()
	router.GET("/client-ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	return router
}

func TestClientIPCloudflarePlatform(t *testing.T) {
	router := clientIPRouter(t, "cloudflare")

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	// A borda Cloudflare também aparece no X-Forwarded-For; o header da
	// plataforma tem precedência.
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 172.71.1.1")
	req.RemoteAddr = "10.0.0.5:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if got := w.Body.String(); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want %q (CF-Connecting-IP)", got, "203.0.113.7")
	}
}

func TestClientIPIgnoresCloudflareHeaderByDefault(t *testing.T) {
	router := clientIPRouter(t, "")

	// Sem TRUSTED_PLATFORM o header CF é forjável: deve ser ignorado.
	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if got := w.Body.String(); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want %q (header CF ignorado)", got, "203.0.113.9")
	}
}

func TestClientIPForwardedForChainDefault(t *testing.T) {
	router := clientIPRouter(t, "")

	// Proxy privado confiável: o primeiro IP público da cadeia é o cliente.
	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.2, 10.0.0.7")
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if got := w.Body.String(); got != "198.51.100.2" {
		t.Errorf("ClientIP = %q, want %q", got, "198.51.100.2")
	}
}
