package http_test

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/crypto"
	httpapi "github.com/apolinario0x21/small-links/internal/http"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"

	"net/http/httptest"
)

// Testes de integração ponta a ponta: servidor HTTP real (httptest) sobre o
// router de produção, repositório real e Postgres real — sem mocks em lugar
// nenhum. Cobrem os fluxos completos do usuário (criar → abrir → medir →
// excluir), que os testes de unidade só enxergam em pedaços.
//
// Gated por SMALL_LINKS_TEST_DATABASE_URL (ver `make test-integration`).

const testEncryptionKey = "0123456789abcdef0123456789abcdef"

// env é o ambiente de um teste: servidor no ar, banco limpo e acesso direto
// ao repositório para montar cenários e conferir efeitos colaterais.
type env struct {
	t        *testing.T
	server   *httptest.Server
	repo     *storage.Postgres
	db       *sql.DB
	cipher   *crypto.Cipher
	recorder *analytics.Recorder
}

func newEnv(t *testing.T) *env {
	t.Helper()

	dsn := os.Getenv("SMALL_LINKS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SMALL_LINKS_TEST_DATABASE_URL não definido; pulando teste de integração")
	}

	gin.SetMode(gin.TestMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("abrir conexão: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := storage.Migrate(db); err != nil {
		t.Fatalf("aplicar migrations: %v", err)
	}
	if _, err := db.Exec(`TRUNCATE urls, click_events RESTART IDENTITY`); err != nil {
		t.Fatalf("limpar tabelas: %v", err)
	}

	cipher, err := crypto.New([]byte(testEncryptionKey))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	repo := storage.NewPostgres(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Sem GeoResolver: a base MMDB não faz parte do ambiente de teste, e o
	// país não classificado já é um caminho coberto ("unknown").
	recorder := analytics.NewRecorder(repo, nil, cipher, logger)

	server := httptest.NewServer(
		httpapi.New(repo, cipher, recorder, nil, logger, httpapi.Options{}).Router(),
	)
	t.Cleanup(server.Close)

	return &env{t: t, server: server, repo: repo, db: db, cipher: cipher, recorder: recorder}
}

// client devolve um cliente que NÃO segue redirects (queremos inspecionar o
// 302) e guarda cookies, como um navegador.
func (e *env) client() *http.Client {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		// DisableKeepAlives: httptest.Server.Close() BLOQUEIA enquanto houver
		// conexão aberta, e cada cliente deixaria a sua ociosa no pool — o
		// pacote levava ~40s de espera pura no teardown, sem teste algum
		// rodando. Sem keep-alive o Close é imediato.
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// shorten cria um link via API e devolve o corpo decodificado.
func (e *env) shorten(body string) (int, map[string]any) {
	e.t.Helper()

	resp, err := e.client().Post(e.server.URL+"/api/shorten", "application/json", strings.NewReader(body))
	if err != nil {
		e.t.Fatalf("POST /api/shorten: %v", err)
	}
	defer resp.Body.Close()

	var decoded map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			e.t.Fatalf("decodificar resposta %q: %v", raw, err)
		}
	}
	return resp.StatusCode, decoded
}

// mustShorten cria um link e exige sucesso, devolvendo o corpo.
func (e *env) mustShorten(body string) map[string]any {
	e.t.Helper()
	status, decoded := e.shorten(body)
	if status != http.StatusCreated && status != http.StatusOK {
		e.t.Fatalf("criar link: status = %d, body = %v", status, decoded)
	}
	return decoded
}

// reply é a resposta já consumida: status, headers e corpo em memória. Os
// helpers devolvem isto (e não *http.Response) para que fechar o corpo seja
// responsabilidade de um único ponto, sem depender de defer em cada teste.
type reply struct {
	status int
	header http.Header
	body   string
}

// read consome e fecha a resposta.
func read(t *testing.T, resp *http.Response, err error, what string) reply {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: ler corpo: %v", what, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func (e *env) get(path string, client *http.Client) reply {
	e.t.Helper()
	resp, err := client.Get(e.server.URL + path)
	return read(e.t, resp, err, "GET "+path)
}

// getHTML dispara um GET com Accept: text/html, como um navegador.
func (e *env) getHTML(path string, client *http.Client) reply {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+path, nil)
	if err != nil {
		e.t.Fatalf("montar GET %s: %v", path, err)
	}
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	return read(e.t, resp, err, "GET (html) "+path)
}

// flushClicks encerra o Recorder, garantindo que os eventos assíncronos já
// foram gravados antes das asserções sobre analytics.
func (e *env) flushClicks() {
	e.t.Helper()
	e.recorder.Close()
}

func (e *env) stats(shortID string) map[string]any {
	e.t.Helper()
	resp := e.get("/stats/"+shortID, e.client())
	if resp.status != http.StatusOK {
		e.t.Fatalf("GET /stats/%s: status = %d", shortID, resp.status)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(resp.body), &decoded); err != nil {
		e.t.Fatalf("decodificar stats: %v", err)
	}
	return decoded
}

func shortIDOf(t *testing.T, created map[string]any) string {
	t.Helper()
	id, _ := created["short_id"].(string)
	if id == "" {
		t.Fatalf("resposta sem short_id: %v", created)
	}
	return id
}

// --- Fluxo completo: criar → redirecionar → medir ---

func TestIntegrationCreateRedirectAndStats(t *testing.T) {
	e := newEnv(t)
	const target = "https://www.exemplo.com/pagina?utm=1"

	created := e.mustShorten(`{"url":"` + target + `"}`)
	shortID := shortIDOf(t, created)

	// A URL nunca é gravada em claro: o que está no banco é ciphertext.
	var stored string
	if err := e.db.QueryRow(`SELECT original_url FROM urls WHERE short_id = $1`, shortID).Scan(&stored); err != nil {
		t.Fatalf("consultar original_url: %v", err)
	}
	if strings.Contains(stored, "exemplo.com") {
		t.Error("a URL original foi gravada em claro no banco")
	}
	if decrypted, err := e.cipher.Decrypt(stored); err != nil || decrypted != target {
		t.Errorf("decifrar: %q, %v; want %q", decrypted, err, target)
	}

	// Redirect resolve para o destino original.
	resp := e.get("/"+shortID, e.client())
	if resp.status != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.status)
	}
	if loc := resp.header.Get("Location"); loc != target {
		t.Errorf("Location = %q, want %q", loc, target)
	}

	e.flushClicks()

	stats := e.stats(shortID)
	if stats["access_count"] != float64(1) {
		t.Errorf("access_count = %v, want 1", stats["access_count"])
	}
	if stats["total_clicks"] != float64(1) {
		t.Errorf("total_clicks = %v, want 1", stats["total_clicks"])
	}
	if stats["original_url"] != target {
		t.Errorf("original_url = %v, want %q", stats["original_url"], target)
	}
}

// O IP do visitante nunca é persistido — só o HMAC.
func TestIntegrationClickStoresOnlyIPHash(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/lgpd"}`)
	shortID := shortIDOf(t, created)

	e.get("/"+shortID, e.client())
	e.flushClicks()

	var ipHash sql.NullString
	err := e.db.QueryRow(`SELECT ip_hash FROM click_events WHERE short_id = $1`, shortID).Scan(&ipHash)
	if err != nil {
		t.Fatalf("consultar click_events: %v", err)
	}
	if !ipHash.Valid || len(ipHash.String) != 64 {
		t.Fatalf("ip_hash = %v, want HMAC de 64 chars", ipHash)
	}
	if strings.Contains(ipHash.String, "127.0.0.1") || strings.Contains(ipHash.String, "::1") {
		t.Error("ip_hash contém o IP em claro")
	}
}

// --- Deduplicação ---

func TestIntegrationDedupReturnsSameLink(t *testing.T) {
	e := newEnv(t)
	const target = "https://www.exemplo.com/dedup"

	first := e.mustShorten(`{"url":"` + target + `"}`)
	status, second := e.shorten(`{"url":"` + target + `"}`)

	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 (dedup)", status)
	}
	if second["existing"] != true {
		t.Errorf("existing = %v, want true", second["existing"])
	}
	if second["short_id"] != first["short_id"] {
		t.Errorf("short_id = %v, want %v", second["short_id"], first["short_id"])
	}
	// O token de gerenciamento só vai para o criador original.
	if _, ok := second["management_token"]; ok {
		t.Error("dedup não pode devolver management_token")
	}
}

// Os dois sentidos do critério: criar COM senha nunca reaproveita o público, e
// criar SEM senha nunca recebe o protegido.
func TestIntegrationDedupIsolatesProtectedLinks(t *testing.T) {
	e := newEnv(t)
	const target = "https://www.exemplo.com/mesmo-destino"

	public := e.mustShorten(`{"url":"` + target + `"}`)
	protected := e.mustShorten(`{"url":"` + target + `","password":"segredo123"}`)

	if protected["short_id"] == public["short_id"] {
		t.Error("criação com senha reaproveitou o link público")
	}
	if protected["has_password"] != true {
		t.Errorf("has_password = %v, want true", protected["has_password"])
	}

	// Excluindo o público, a próxima criação sem senha também não pode cair
	// no protegido — precisa nascer um link novo.
	e.mustDelete(shortIDOf(t, public), public["management_token"].(string))

	third := e.mustShorten(`{"url":"` + target + `"}`)
	if third["short_id"] == protected["short_id"] {
		t.Error("criação sem senha recebeu um link protegido (não conseguiria abrir)")
	}
	if third["existing"] == true {
		t.Error("não havia link reaproveitável; deveria criar um novo")
	}
}

// --- Alias, expiração e erros de criação ---

func TestIntegrationCustomAliasLifecycle(t *testing.T) {
	e := newEnv(t)

	created := e.mustShorten(`{"url":"https://www.exemplo.com/promo","custom_alias":"promo-verao"}`)
	if created["short_id"] != "promo-verao" {
		t.Fatalf("short_id = %v, want promo-verao", created["short_id"])
	}

	resp := e.get("/promo-verao", e.client())
	if resp.status != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.status)
	}

	// Alias já em uso → 409.
	if status, _ := e.shorten(`{"url":"https://www.exemplo.com/outra","custom_alias":"promo-verao"}`); status != http.StatusConflict {
		t.Errorf("alias repetido: status = %d, want 409", status)
	}

	// Alias reservado → 409.
	if status, _ := e.shorten(`{"url":"https://www.exemplo.com/x","custom_alias":"metrics"}`); status != http.StatusConflict {
		t.Errorf("alias reservado: status = %d, want 409", status)
	}
}

func TestIntegrationExpiredLinkReturnsGone(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/ttl","expires_in_days":1}`)
	shortID := shortIDOf(t, created)

	// Empurra a expiração para o passado direto no banco: esperar um dia não
	// é opção, e é exatamente o estado que o handler precisa reconhecer.
	if _, err := e.db.Exec(`UPDATE urls SET expires_at = now() - interval '1 hour' WHERE short_id = $1`, shortID); err != nil {
		t.Fatalf("expirar link: %v", err)
	}

	resp := e.get("/"+shortID, e.client())
	if resp.status != http.StatusGone {
		t.Errorf("status = %d, want 410", resp.status)
	}

	// Link expirado também não é reaproveitado pelo dedup.
	again := e.mustShorten(`{"url":"https://www.exemplo.com/ttl"}`)
	if again["short_id"] == shortID {
		t.Error("dedup devolveu um link expirado")
	}
}

func TestIntegrationInvalidCreationRequests(t *testing.T) {
	e := newEnv(t)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"URL vazia", `{"url":""}`, http.StatusBadRequest},
		{"esquema inválido", `{"url":"ftp://exemplo.com"}`, http.StatusBadRequest},
		{"body não-JSON", `nao-e-json`, http.StatusBadRequest},
		{"alias fora do padrão", `{"url":"https://exemplo.com","custom_alias":"a!"}`, http.StatusBadRequest},
		{"expiração não positiva", `{"url":"https://exemplo.com","expires_in_days":0}`, http.StatusBadRequest},
		{"senha curta", `{"url":"https://exemplo.com","password":"abc"}`, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if status, _ := e.shorten(tc.body); status != tc.want {
				t.Errorf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

// --- Links protegidos por senha ---

func TestIntegrationPasswordProtectedFlow(t *testing.T) {
	e := newEnv(t)
	const target = "https://www.exemplo.com/relatorio-confidencial"

	created := e.mustShorten(`{"url":"` + target + `","password":"segredo123"}`)
	shortID := shortIDOf(t, created)

	// Só o hash é persistido.
	var stored string
	if err := e.db.QueryRow(`SELECT password_hash FROM urls WHERE short_id = $1`, shortID).Scan(&stored); err != nil {
		t.Fatalf("consultar password_hash: %v", err)
	}
	if stored == "segredo123" || !strings.HasPrefix(stored, "$2") {
		t.Errorf("password_hash = %q, want bcrypt", stored)
	}

	client := e.client()

	// Sem cookie: cliente de API recebe 401 e nada sobre o destino.
	resp := e.get("/"+shortID, client)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.status)
	}
	if strings.Contains(resp.body, "relatorio-confidencial") {
		t.Error("resposta 401 vazou o destino")
	}

	// Navegador: tela de senha, também sem o destino.
	page := e.getHTML("/"+shortID, client)
	if page.status != http.StatusOK || !strings.Contains(page.body, `name="password"`) {
		t.Fatalf("tela de senha: status = %d", page.status)
	}
	if strings.Contains(page.body, "relatorio-confidencial") {
		t.Error("a tela de senha vazou o destino")
	}

	// Senha errada não autoriza.
	wrong := e.submitPassword(client, shortID, "errada123")
	if wrong.status != http.StatusUnauthorized {
		t.Errorf("senha errada: status = %d, want 401", wrong.status)
	}

	// Senha correta: 302 e cookie de acesso emitido.
	right := e.submitPassword(client, shortID, "segredo123")
	if right.status != http.StatusFound {
		t.Fatalf("senha correta: status = %d, want 302", right.status)
	}
	if loc := right.header.Get("Location"); loc != target {
		t.Errorf("Location = %q, want %q", loc, target)
	}

	// Com o cookie no jar, o GET seguinte redireciona direto.
	after := e.get("/"+shortID, client)
	if after.status != http.StatusFound {
		t.Errorf("com cookie: status = %d, want 302", after.status)
	}

	// Um cliente novo (sem cookie) continua barrado.
	if fresh := e.get("/"+shortID, e.client()); fresh.status != http.StatusUnauthorized {
		t.Errorf("cliente sem cookie: status = %d, want 401", fresh.status)
	}

	// Analytics: só os dois redirects concluídos viraram clique — a tela de
	// senha e a tentativa errada, não.
	e.flushClicks()
	if stats := e.stats(shortID); stats["total_clicks"] != float64(2) {
		t.Errorf("total_clicks = %v, want 2 (só redirects concluídos)", stats["total_clicks"])
	}
}

// submitPassword envia a senha via formulário, como a tela faz.
func (e *env) submitPassword(client *http.Client, shortID, password string) reply {
	e.t.Helper()
	resp, err := client.PostForm(e.server.URL+"/"+shortID, url.Values{"password": {password}})
	return read(e.t, resp, err, "POST senha")
}

// Caminho do NAVEGADOR ponta a ponta: envia o formulário com Accept: text/html
// e recebe, na MESMA resposta, o cookie e o 302 para o destino.
//
// Regressão do bug em que a diretiva `form-action 'self'` da CSP bloqueava a
// navegação: o cookie era gravado, mas o usuário ficava na tela de senha e
// precisava acessar o link outra vez. Aqui verificamos as duas metades da
// correção — a resposta certa E a política que permite o navegador segui-la.
func TestIntegrationPasswordSubmitFromBrowserReachesTarget(t *testing.T) {
	e := newEnv(t)
	const target = "https://www.exemplo.com/destino-do-navegador"

	created := e.mustShorten(`{"url":"` + target + `","password":"segredo123"}`)
	shortID := shortIDOf(t, created)

	client := e.client()

	// A CSP da tela de senha não pode restringir form-action, senão o
	// navegador aborta o envio antes mesmo de sair da página.
	page := e.getHTML("/"+shortID, client)
	if strings.Contains(page.header.Get("Content-Security-Policy"), "form-action") {
		t.Fatalf("CSP da tela de senha restringe form-action: %q", page.header.Get("Content-Security-Policy"))
	}

	// Envio do formulário: 302 para o destino + cookie na MESMA resposta.
	form := url.Values{"password": {"segredo123"}}
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/"+shortID, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("montar POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	posted := read(t, resp, err, "POST senha (navegador)")

	if posted.status != http.StatusFound {
		t.Fatalf("status = %d, want 302", posted.status)
	}
	if loc := posted.header.Get("Location"); loc != target {
		t.Fatalf("Location = %q, want %q", loc, target)
	}
	if posted.header.Get("Set-Cookie") == "" {
		t.Fatal("Set-Cookie ausente na resposta do redirect")
	}

	// E o cookie recebido serve para o acesso seguinte, sem nova senha.
	again := e.get("/"+shortID, client)
	if again.status != http.StatusFound || again.header.Get("Location") != target {
		t.Errorf("acesso seguinte: status = %d, Location = %q", again.status, again.header.Get("Location"))
	}
}

// Expiração tem precedência sobre a senha: link morto responde 410 sem nunca
// mostrar a tela.
func TestIntegrationExpiredProtectedLinkReturnsGone(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/secreto","password":"segredo123","expires_in_days":1}`)
	shortID := shortIDOf(t, created)

	if _, err := e.db.Exec(`UPDATE urls SET expires_at = now() - interval '1 hour' WHERE short_id = $1`, shortID); err != nil {
		t.Fatalf("expirar link: %v", err)
	}

	resp := e.getHTML("/"+shortID, e.client())

	if resp.status != http.StatusGone {
		t.Fatalf("status = %d, want 410", resp.status)
	}
	if strings.Contains(resp.body, `name="password"`) {
		t.Error("link expirado exibiu a tela de senha")
	}
}

// Força bruta no mesmo link acaba barrada por 429.
//
// O laço tolera mais que as 5 tentativas do burst de propósito: cada tentativa
// custa um bcrypt de custo 12 (segundos sob -race), e nesse intervalo o limiter
// já recarregou parte dos tokens. Como o consumo é mais rápido que a recarga
// (5/min), o 429 é inevitável — o que não dá para fixar é em QUAL tentativa ele
// cai. Fixar "a 6ª" tornava o teste dependente da velocidade da máquina, e foi
// exatamente assim que ele falhou sob -race.
func TestIntegrationPasswordBruteForceIsRateLimited(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/alvo","password":"segredo123"}`)
	shortID := shortIDOf(t, created)

	const maxAttempts = 20
	client := e.client()

	for i := 1; i <= maxAttempts; i++ {
		resp := e.submitPassword(client, shortID, "errada123")
		if resp.status == http.StatusTooManyRequests {
			return // barrado, como esperado
		}
		if resp.status != http.StatusUnauthorized {
			t.Fatalf("tentativa %d: status = %d, want 401 ou 429", i, resp.status)
		}
	}

	t.Errorf("nenhuma das %d tentativas foi barrada com 429", maxAttempts)
}

// --- Exclusão por token ---

// mustDelete exclui o link exigindo 204.
func (e *env) mustDelete(shortID, token string) {
	e.t.Helper()
	if status := e.delete(shortID, token); status != http.StatusNoContent {
		e.t.Fatalf("DELETE %s: status = %d, want 204", shortID, status)
	}
}

func (e *env) delete(shortID, token string) int {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodDelete, e.server.URL+"/api/links/"+shortID, nil)
	if err != nil {
		e.t.Fatalf("montar DELETE: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.client().Do(req)
	return read(e.t, resp, err, "DELETE "+shortID).status
}

func TestIntegrationDeleteLifecycle(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/temporario"}`)
	shortID := shortIDOf(t, created)
	token, _ := created["management_token"].(string)
	if len(token) != 64 {
		t.Fatalf("management_token = %q, want 64 hex chars", token)
	}

	// O token em claro nunca é persistido — só o SHA-256.
	var storedHash string
	if err := e.db.QueryRow(`SELECT management_token_hash FROM urls WHERE short_id = $1`, shortID).Scan(&storedHash); err != nil {
		t.Fatalf("consultar hash do token: %v", err)
	}
	if storedHash == token {
		t.Error("o token de gerenciamento foi persistido em claro")
	}
	if storedHash != crypto.TokenSHA256(token) {
		t.Error("management_token_hash não é o SHA-256 do token devolvido")
	}

	// Token errado e ausente: 403 uniforme (não revela que o link existe).
	if status := e.delete(shortID, strings.Repeat("f", 64)); status != http.StatusForbidden {
		t.Errorf("token errado: status = %d, want 403", status)
	}
	if status := e.delete(shortID, ""); status != http.StatusForbidden {
		t.Errorf("sem token: status = %d, want 403", status)
	}
	if status := e.delete("naoexiste", strings.Repeat("f", 64)); status != http.StatusForbidden {
		t.Errorf("link inexistente: status = %d, want 403 (uniforme)", status)
	}

	// Token correto: 204 e, daí em diante, 410 no redirect e no QR.
	e.mustDelete(shortID, token)

	if resp := e.get("/"+shortID, e.client()); resp.status != http.StatusGone {
		t.Errorf("redirect após exclusão: status = %d, want 410", resp.status)
	}
	if resp := e.get("/qr/"+shortID, e.client()); resp.status != http.StatusGone {
		t.Errorf("QR após exclusão: status = %d, want 410", resp.status)
	}

	// Stats continua acessível (o analytics é preservado).
	if resp := e.get("/stats/"+shortID, e.client()); resp.status != http.StatusOK {
		t.Errorf("stats após exclusão: status = %d, want 200", resp.status)
	}

	// E o short_id não pode ser reciclado como alias novo.
	if status, _ := e.shorten(`{"url":"https://www.exemplo.com/golpe","custom_alias":"` + shortID + `"}`); status != http.StatusConflict {
		t.Errorf("reciclagem do short_id: status = %d, want 409", status)
	}
}

// --- QR code, health e rotas auxiliares ---

func TestIntegrationQRCode(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/qr"}`)
	shortID := shortIDOf(t, created)

	resp := e.get("/qr/"+shortID, e.client())
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	if ct := resp.header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if !strings.HasPrefix(resp.body, "\x89PNG") {
		t.Error("corpo não é um PNG")
	}

	if resp := e.get("/qr/naoexiste", e.client()); resp.status != http.StatusNotFound {
		t.Errorf("QR de link inexistente: status = %d, want 404", resp.status)
	}
}

func TestIntegrationHealthReflectsDatabase(t *testing.T) {
	e := newEnv(t)

	resp := e.get("/health", e.client())
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	var health map[string]any
	if err := json.Unmarshal([]byte(resp.body), &health); err != nil {
		t.Fatalf("decodificar health: %v", err)
	}
	if health["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", health["status"])
	}
	if health["total_urls"] != float64(0) {
		t.Fatalf("total_urls = %v, want 0", health["total_urls"])
	}

	e.mustShorten(`{"url":"https://www.exemplo.com/health"}`)

	resp = e.get("/health", e.client())
	if err := json.Unmarshal([]byte(resp.body), &health); err != nil {
		t.Fatalf("decodificar health: %v", err)
	}
	if health["total_urls"] != float64(1) {
		t.Errorf("total_urls = %v, want 1", health["total_urls"])
	}
}

func TestIntegrationRedirectUnknownShortID(t *testing.T) {
	e := newEnv(t)

	if resp := e.get("/naoexiste", e.client()); resp.status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.status)
	}
	if resp := e.get("/stats/naoexiste", e.client()); resp.status != http.StatusNotFound {
		t.Errorf("stats: status = %d, want 404", resp.status)
	}
}

// A landing e as métricas continuam servidas com o catch-all /:shortId
// registrado — rota estática e param não podem colidir.
func TestIntegrationStaticRoutesCoexistWithCatchAll(t *testing.T) {
	e := newEnv(t)

	landing := e.get("/", e.client())
	if landing.status != http.StatusOK {
		t.Errorf("landing: status = %d, want 200", landing.status)
	}
	if ct := landing.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("landing Content-Type = %q", ct)
	}

	metrics := e.get("/metrics", e.client())
	if metrics.status != http.StatusOK {
		t.Fatalf("metrics: status = %d, want 200", metrics.status)
	}
	if !strings.Contains(metrics.body, "smalllinks_shortens_total") {
		t.Error("/metrics não expõe os coletores da aplicação")
	}
}

// --- Analytics agregado ---

func TestIntegrationStatsAggregatesRealClicks(t *testing.T) {
	e := newEnv(t)
	created := e.mustShorten(`{"url":"https://www.exemplo.com/agregado"}`)
	shortID := shortIDOf(t, created)

	client := e.client()
	// Três acessos humanos + um bot (que fica fora das agregações).
	for i := 0; i < 3; i++ {
		e.get("/"+shortID, client)
	}
	botReq, err := http.NewRequest(http.MethodGet, e.server.URL+"/"+shortID, nil)
	if err != nil {
		t.Fatalf("montar requisição do bot: %v", err)
	}
	botReq.Header.Set("User-Agent", "Googlebot/2.1 (+http://www.google.com/bot.html)")
	botResp, err := client.Do(botReq)
	read(t, botResp, err, "GET (bot)")

	e.flushClicks()
	stats := e.stats(shortID)

	// access_count conta TODOS os acessos; as agregações excluem bots.
	if stats["access_count"] != float64(4) {
		t.Errorf("access_count = %v, want 4", stats["access_count"])
	}
	if stats["total_clicks"] != float64(3) {
		t.Errorf("total_clicks = %v, want 3 (bot excluído)", stats["total_clicks"])
	}

	// Invariante das somas: devices e países batem com o total.
	sum := func(key string) int {
		total := 0
		for _, item := range stats[key].([]any) {
			total += int(item.(map[string]any)["count"].(float64))
		}
		return total
	}
	if got := sum("devices"); got != 3 {
		t.Errorf("soma(devices) = %d, want 3", got)
	}
	if got := sum("top_countries"); got != 3 {
		t.Errorf("soma(top_countries) = %d, want 3", got)
	}

	// Sem base GeoIP no ambiente de teste, o país entra como "unknown" —
	// jamais é omitido.
	countries := stats["top_countries"].([]any)
	if len(countries) != 1 || countries[0].(map[string]any)["country"] != "unknown" {
		t.Errorf("top_countries = %v, want [unknown]", countries)
	}

	// clicks_per_day traz o dia de hoje.
	perDay := stats["clicks_per_day"].([]any)
	if len(perDay) != 1 {
		t.Fatalf("clicks_per_day = %v, want 1 dia", perDay)
	}
	if day := perDay[0].(map[string]any)["day"]; day != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("day = %v, want hoje", day)
	}
}
