package http

import (
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

func setupTest(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { mockDB.Close() })

	server := New(storage.NewPostgres(mockDB), testCipher, slog.New(slog.NewTextHandler(io.Discard, nil)))

	return server.Router(), mock
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

func TestShortenSuccess(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectExec(`INSERT INTO urls \(short_id, original_url, created_at, access_count\) VALUES \(\$1, \$2, \$3, \$4\)`).
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

// --- GET /:shortId ---

func TestRedirectSuccess(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com/destino")
	mock.ExpectQuery(`SELECT short_id, original_url, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count"}).
			AddRow("abc123", encrypted, 7))
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

	mock.ExpectQuery(`SELECT short_id, original_url, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("naoexi").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count"}))

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

// Caracteriza: falha ao incrementar access_count NÃO impede o redirect.
func TestRedirectUpdateFailureStillRedirects(t *testing.T) {
	router, mock := setupTest(t)

	encrypted := encrypt("https://www.example.com")
	mock.ExpectQuery(`SELECT short_id, original_url, access_count FROM urls`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "access_count"}).
			AddRow("abc123", encrypted, 0))
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

func TestStatsSuccess(t *testing.T) {
	router, mock := setupTest(t)

	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	encrypted := encrypt("https://www.example.com")
	mock.ExpectQuery(`SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = \$1`).
		WithArgs("abc123").
		WillReturnRows(sqlmock.NewRows([]string{"short_id", "original_url", "created_at", "access_count"}).
			AddRow("abc123", encrypted, createdAt, 42))

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

	w := doRequest(router, http.MethodOptions, "/health")

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", origin, "*")
	}
	expectations(t, mock)
}
