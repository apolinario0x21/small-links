package storage_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/apolinario0x21/small-links/internal/storage"
)

// Testes de integração do repositório contra um Postgres REAL. Aqui é onde as
// invariantes que vivem no SQL — critério de exclusão do dedup, soft delete
// que impede reciclagem de short_id, mapeamento de erros do driver — podem ser
// verificadas de verdade: contra um mock só se reafirmaria a string da query.
//
// Gated por SMALL_LINKS_TEST_DATABASE_URL (ver Makefile: make test-integration).

// newRepo abre a conexão, aplica as migrations e devolve o repositório com a
// tabela limpa. Pular acontece uma única vez, aqui.
func newRepo(t *testing.T) (*storage.Postgres, *sql.DB) {
	t.Helper()

	db := openTestDB(t)
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("aplicar migrations: %v", err)
	}
	truncateAll(t, db)

	return storage.NewPostgres(db), db
}

func truncateAll(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`TRUNCATE urls, click_events RESTART IDENTITY`); err != nil {
		t.Fatalf("limpar tabelas: %v", err)
	}
}

// newURL monta um URLData válido; os campos opcionais ficam a cargo do teste.
func newURL(shortID, hash string) storage.URLData {
	return storage.URLData{
		ShortID:     shortID,
		OriginalURL: "ciphertext-" + shortID,
		URLHash:     hash,
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
}

func mustInsert(t *testing.T, repo *storage.Postgres, data storage.URLData) {
	t.Helper()
	if err := repo.Insert(context.Background(), data); err != nil {
		t.Fatalf("insert %s: %v", data.ShortID, err)
	}
}

// --- Migrations ---

// As migrations rodam a cada boot, então precisam ser idempotentes.
func TestMigrateIsIdempotent(t *testing.T) {
	db := openTestDB(t)

	for i := 0; i < 3; i++ {
		if err := storage.Migrate(db); err != nil {
			t.Fatalf("migrate (execução %d): %v", i+1, err)
		}
	}

	// Todas as colunas acrescentadas por migrations posteriores à 001 devem
	// existir ao final.
	for _, col := range []string{"url_hash", "expires_at", "management_token_hash", "deleted_at", "password_hash"} {
		var exists bool
		err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'urls' AND column_name = $1)`,
			col,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("consultar coluna %s: %v", col, err)
		}
		if !exists {
			t.Errorf("coluna urls.%s ausente após as migrations", col)
		}
	}
}

// A migration 005 alargou short_id para 30 chars nas duas tabelas; um alias
// longo precisa caber (o bug original respondia 500).
func TestShortIDColumnFitsLongAlias(t *testing.T) {
	repo, _ := newRepo(t)
	long := strings.Repeat("a", 30)

	mustInsert(t, repo, newURL(long, "hash-longo"))

	if _, err := repo.FindByShortID(context.Background(), long); err != nil {
		t.Errorf("alias de 30 chars não sobreviveu ao insert: %v", err)
	}
}

// --- Insert: mapeamento de erros do driver ---

func TestInsertDuplicateShortID(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("dup001", "hash-a"))

	err := repo.Insert(context.Background(), newURL("dup001", "hash-b"))

	if !errors.Is(err, storage.ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestInsertValueTooLong(t *testing.T) {
	repo, _ := newRepo(t)

	err := repo.Insert(context.Background(), newURL(strings.Repeat("x", 31), "hash-x"))

	if !errors.Is(err, storage.ErrValueTooLong) {
		t.Errorf("err = %v, want ErrValueTooLong", err)
	}
}

// Campos vazios precisam virar NULL (NULLIF), não string vazia: as consultas
// de dedup e de gerenciamento testam IS NULL.
func TestInsertStoresEmptyOptionalsAsNull(t *testing.T) {
	repo, db := newRepo(t)
	mustInsert(t, repo, newURL("nulls1", "hash-nulls"))

	var tokenHash, passwordHash sql.NullString
	err := db.QueryRow(`SELECT management_token_hash, password_hash FROM urls WHERE short_id = $1`, "nulls1").
		Scan(&tokenHash, &passwordHash)
	if err != nil {
		t.Fatalf("consultar colunas: %v", err)
	}
	if tokenHash.Valid {
		t.Errorf("management_token_hash = %q, want NULL", tokenHash.String)
	}
	if passwordHash.Valid {
		t.Errorf("password_hash = %q, want NULL", passwordHash.String)
	}
}

// --- Dedup: o critério de exclusão vive na query ---

func TestFindByURLHashReturnsActiveLink(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("ativo1", "hash-dedup"))

	found, err := repo.FindByURLHash(context.Background(), "hash-dedup")
	if err != nil {
		t.Fatalf("FindByURLHash: %v", err)
	}
	if found.ShortID != "ativo1" {
		t.Errorf("ShortID = %q, want ativo1", found.ShortID)
	}
}

func TestFindByURLHashNotFound(t *testing.T) {
	repo, _ := newRepo(t)

	if _, err := repo.FindByURLHash(context.Background(), "hash-inexistente"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// Expirado, deletado e protegido por senha compartilham o MESMO critério de
// exclusão do dedup — nenhum deles pode ser reaproveitado.
func TestFindByURLHashExcludesUnusableLinks(t *testing.T) {
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name   string
		mutate func(*storage.URLData)
	}{
		{"expirado", func(u *storage.URLData) { u.ExpiresAt = &past }},
		{"protegido por senha", func(u *storage.URLData) { u.PasswordHash = "$2a$12$hash-falso" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo, _ := newRepo(t)
			data := newURL("excl01", "hash-excluido")
			tc.mutate(&data)
			mustInsert(t, repo, data)

			if _, err := repo.FindByURLHash(context.Background(), "hash-excluido"); !errors.Is(err, storage.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound (link %s não pode ser reaproveitado)", err, tc.name)
			}
		})
	}

	t.Run("deletado", func(t *testing.T) {
		repo, _ := newRepo(t)
		mustInsert(t, repo, newURL("excl02", "hash-deletado"))
		if _, err := repo.SoftDelete(context.Background(), "excl02"); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}

		if _, err := repo.FindByURLHash(context.Background(), "hash-deletado"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound (link deletado não pode ser reaproveitado)", err)
		}
	})
}

// Com um link morto e um vivo para a mesma URL, o dedup devolve o vivo.
func TestFindByURLHashPrefersUsableLink(t *testing.T) {
	repo, _ := newRepo(t)
	past := time.Now().Add(-time.Hour)

	dead := newURL("morto1", "hash-misto")
	dead.ExpiresAt = &past
	mustInsert(t, repo, dead)
	mustInsert(t, repo, newURL("vivo01", "hash-misto"))

	found, err := repo.FindByURLHash(context.Background(), "hash-misto")
	if err != nil {
		t.Fatalf("FindByURLHash: %v", err)
	}
	if found.ShortID != "vivo01" {
		t.Errorf("ShortID = %q, want vivo01", found.ShortID)
	}
}

// --- FindForRedirect ---

func TestFindForRedirectCarriesLinkState(t *testing.T) {
	repo, _ := newRepo(t)
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	data := newURL("redir1", "hash-redirect")
	data.ExpiresAt = &future
	data.PasswordHash = "$2a$12$hash-falso"
	mustInsert(t, repo, data)

	found, err := repo.FindForRedirect(context.Background(), "redir1")
	if err != nil {
		t.Fatalf("FindForRedirect: %v", err)
	}
	if found.OriginalURL != data.OriginalURL {
		t.Errorf("OriginalURL = %q, want %q", found.OriginalURL, data.OriginalURL)
	}
	if found.ExpiresAt == nil || !found.ExpiresAt.UTC().Equal(future) {
		t.Errorf("ExpiresAt = %v, want %v", found.ExpiresAt, future)
	}
	if found.PasswordHash != data.PasswordHash {
		t.Errorf("PasswordHash = %q, want %q", found.PasswordHash, data.PasswordHash)
	}
	if found.DeletedAt != nil {
		t.Errorf("DeletedAt = %v, want nil", found.DeletedAt)
	}
}

// Link público precisa devolver PasswordHash vazio (coluna NULL), e não
// disparar erro de Scan.
func TestFindForRedirectPublicLinkHasEmptyPasswordHash(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("publi1", "hash-publico"))

	found, err := repo.FindForRedirect(context.Background(), "publi1")
	if err != nil {
		t.Fatalf("FindForRedirect: %v", err)
	}
	if found.PasswordHash != "" {
		t.Errorf("PasswordHash = %q, want vazio", found.PasswordHash)
	}
}

// Deletado continua sendo encontrado (com DeletedAt): quem decide o 410 é o
// handler, não o repositório.
func TestFindForRedirectFindsDeletedWithTimestamp(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("morto2", "hash-morto"))
	if _, err := repo.SoftDelete(context.Background(), "morto2"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	found, err := repo.FindForRedirect(context.Background(), "morto2")
	if err != nil {
		t.Fatalf("FindForRedirect: %v", err)
	}
	if found.DeletedAt == nil {
		t.Error("DeletedAt = nil, want preenchido")
	}
}

func TestFindForRedirectNotFound(t *testing.T) {
	repo, _ := newRepo(t)

	if _, err := repo.FindForRedirect(context.Background(), "nada00"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestFindByShortIDNotFound(t *testing.T) {
	repo, _ := newRepo(t)

	if _, err := repo.FindByShortID(context.Background(), "nada00"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// --- Contadores ---

func TestIncrementAccessCount(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("conta1", "hash-conta"))

	for i := 0; i < 3; i++ {
		if err := repo.IncrementAccessCount(context.Background(), "conta1"); err != nil {
			t.Fatalf("IncrementAccessCount: %v", err)
		}
	}

	found, err := repo.FindByShortID(context.Background(), "conta1")
	if err != nil {
		t.Fatalf("FindByShortID: %v", err)
	}
	if found.AccessCount != 3 {
		t.Errorf("AccessCount = %d, want 3", found.AccessCount)
	}
}

// Incrementar link inexistente não é erro (0 linhas afetadas) — o redirect
// nunca deve quebrar por causa do contador.
func TestIncrementAccessCountUnknownLinkIsNoOp(t *testing.T) {
	repo, _ := newRepo(t)

	if err := repo.IncrementAccessCount(context.Background(), "nada00"); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestCountURLs(t *testing.T) {
	repo, _ := newRepo(t)

	total, err := repo.CountURLs(context.Background())
	if err != nil {
		t.Fatalf("CountURLs: %v", err)
	}
	if total != 0 {
		t.Fatalf("total inicial = %d, want 0", total)
	}

	mustInsert(t, repo, newURL("cnt001", "hash-c1"))
	mustInsert(t, repo, newURL("cnt002", "hash-c2"))

	total, err = repo.CountURLs(context.Background())
	if err != nil {
		t.Fatalf("CountURLs: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

// --- Gerenciamento e soft delete ---

func TestManagementHashDistinguishesCases(t *testing.T) {
	repo, _ := newRepo(t)

	withToken := newURL("gerid1", "hash-g1")
	withToken.ManagementTokenHash = strings.Repeat("a", 64)
	mustInsert(t, repo, withToken)
	mustInsert(t, repo, newURL("antigo", "hash-g2")) // sem token: link legado

	tests := []struct {
		name       string
		shortID    string
		wantHash   string
		wantExists bool
	}{
		{"com token", "gerid1", withToken.ManagementTokenHash, true},
		{"sem token (legado)", "antigo", "", true},
		{"inexistente", "nada00", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, exists, err := repo.ManagementHash(context.Background(), tc.shortID)
			if err != nil {
				t.Fatalf("ManagementHash: %v", err)
			}
			if hash != tc.wantHash {
				t.Errorf("hash = %q, want %q", hash, tc.wantHash)
			}
			if exists != tc.wantExists {
				t.Errorf("exists = %v, want %v", exists, tc.wantExists)
			}
		})
	}
}

// O token continua consultável após o soft delete (a exclusão é idempotente).
func TestManagementHashSurvivesSoftDelete(t *testing.T) {
	repo, _ := newRepo(t)
	data := newURL("gerid2", "hash-g3")
	data.ManagementTokenHash = strings.Repeat("b", 64)
	mustInsert(t, repo, data)

	if _, err := repo.SoftDelete(context.Background(), "gerid2"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	hash, exists, err := repo.ManagementHash(context.Background(), "gerid2")
	if err != nil {
		t.Fatalf("ManagementHash: %v", err)
	}
	if !exists || hash != data.ManagementTokenHash {
		t.Errorf("hash = %q, exists = %v; o token deve sobreviver ao soft delete", hash, exists)
	}
}

func TestSoftDeleteIsIdempotent(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("delid1", "hash-d1"))

	first, err := repo.SoftDelete(context.Background(), "delid1")
	if err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if !first {
		t.Error("primeira exclusão = false, want true (alterou a linha)")
	}

	second, err := repo.SoftDelete(context.Background(), "delid1")
	if err != nil {
		t.Fatalf("SoftDelete (2ª): %v", err)
	}
	if second {
		t.Error("segunda exclusão = true, want false (nada a alterar)")
	}
}

func TestSoftDeleteUnknownLink(t *testing.T) {
	repo, _ := newRepo(t)

	deleted, err := repo.SoftDelete(context.Background(), "nada00")
	if err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if deleted {
		t.Error("deleted = true para link inexistente")
	}
}

// A razão de ser do soft delete: o short_id do link excluído NÃO pode ser
// reciclado como alias novo (golpe de reciclagem).
func TestSoftDeletedShortIDCannotBeRecycled(t *testing.T) {
	repo, _ := newRepo(t)
	mustInsert(t, repo, newURL("recicl", "hash-r1"))
	if _, err := repo.SoftDelete(context.Background(), "recicl"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	err := repo.Insert(context.Background(), newURL("recicl", "hash-r2"))

	if !errors.Is(err, storage.ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate — short_id deletado não pode ser reusado", err)
	}
}

// --- Eventos de clique ---

func TestInsertClickEventStoresEmptyFieldsAsNull(t *testing.T) {
	repo, db := newRepo(t)
	mustInsert(t, repo, newURL("click1", "hash-click"))

	err := repo.InsertClickEvent(context.Background(), storage.ClickEvent{ShortID: "click1"})
	if err != nil {
		t.Fatalf("InsertClickEvent: %v", err)
	}

	var referrer, userAgent, ipHash, country, device sql.NullString
	err = db.QueryRow(
		`SELECT referrer, user_agent, ip_hash, country, device FROM click_events WHERE short_id = $1`, "click1",
	).Scan(&referrer, &userAgent, &ipHash, &country, &device)
	if err != nil {
		t.Fatalf("consultar evento: %v", err)
	}
	for name, col := range map[string]sql.NullString{
		"referrer": referrer, "user_agent": userAgent, "ip_hash": ipHash,
		"country": country, "device": device,
	} {
		if col.Valid {
			t.Errorf("%s = %q, want NULL (campo vazio não pode poluir as agregações)", name, col.String)
		}
	}
}

// click_events não tem FK para urls: o insert é assíncrono e não pode falhar
// por causa de um link removido no meio do caminho.
func TestInsertClickEventAcceptsUnknownShortID(t *testing.T) {
	repo, _ := newRepo(t)

	err := repo.InsertClickEvent(context.Background(), storage.ClickEvent{ShortID: "fantas"})

	if err != nil {
		t.Errorf("err = %v; click_events não deve ter FK para urls", err)
	}
}

// --- Contexto cancelado ---

// Toda query usa context com timeout; contexto já cancelado precisa devolver
// erro em vez de bloquear.
func TestQueriesRespectCanceledContext(t *testing.T) {
	repo, _ := newRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := repo.CountURLs(ctx); err == nil {
		t.Error("CountURLs com contexto cancelado deveria falhar")
	}
	if err := repo.Insert(ctx, newURL("ctx001", "hash-ctx")); err == nil {
		t.Error("Insert com contexto cancelado deveria falhar")
	}
}
