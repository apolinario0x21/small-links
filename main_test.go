package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

// Testes de caracterização: capturam o comportamento ATUAL dos 4 endpoints,
// com o banco substituído por go-sqlmock através da variável global db.

const testKey = "0123456789abcdef0123456789abcdef"

var errTest = errors.New("simulated database error")

func setupTest(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	secretKey = []byte(testKey)

	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	db = mockDB
	repo = storage.NewPostgres(mockDB)
	t.Cleanup(func() { mockDB.Close() })

	return setupRouter(), mock
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
	if body["error"] != "URL must start with http:// or https://" {
		t.Errorf("error = %q, want %q", body["error"], "URL must start with http:// or https://")
	}
	expectations(t, mock)
}

func TestShortenSuccess(t *testing.T) {
	router, mock := setupTest(t)

	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM urls WHERE short_id = \$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
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

	mock.ExpectQuery(`SELECT EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
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
