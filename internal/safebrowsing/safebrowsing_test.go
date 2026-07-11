package safebrowsing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestClient aponta o Client para um servidor httptest.
func newTestClient(srv *httptest.Server) *Client {
	return &Client{
		apiKey:     "test-key",
		endpoint:   srv.URL,
		httpClient: srv.Client(),
	}
}

func TestMaliciousCleanURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resposta vazia = sem ameaças.
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	blocked, err := newTestClient(srv).Malicious(context.Background(), "https://exemplo.com")
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if blocked {
		t.Error("URL limpa não deveria ser bloqueada")
	}
}

func TestMaliciousFlaggedURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"matches":[{"threatType":"MALWARE"}]}`))
	}))
	defer srv.Close()

	blocked, err := newTestClient(srv).Malicious(context.Background(), "http://malware.test")
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !blocked {
		t.Error("URL com match deveria ser bloqueada")
	}
}

func TestMaliciousAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	blocked, err := newTestClient(srv).Malicious(context.Background(), "https://exemplo.com")
	if err == nil {
		t.Error("erro esperado quando a API responde 500")
	}
	if blocked {
		t.Error("bloqueio nunca deve ocorrer em erro de API (fail-open é do chamador)")
	}
}

func TestMaliciousSendsThreatTypes(t *testing.T) {
	var body findRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).Malicious(context.Background(), "https://exemplo.com"); err != nil {
		t.Fatal(err)
	}
	if len(body.ThreatInfo.ThreatTypes) != 4 {
		t.Errorf("threatTypes = %v, want 4 tipos", body.ThreatInfo.ThreatTypes)
	}
	if len(body.ThreatInfo.ThreatEntries) != 1 || body.ThreatInfo.ThreatEntries[0].URL != "https://exemplo.com" {
		t.Errorf("threatEntries = %v", body.ThreatInfo.ThreatEntries)
	}
}
