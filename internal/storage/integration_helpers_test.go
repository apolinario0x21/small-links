package storage_test

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// openTestDB abre a conexão com o Postgres de teste, pulando o teste quando
// SMALL_LINKS_TEST_DATABASE_URL não está definida — o `go test` do CI padrão
// roda sem banco. Ver `make test-integration`.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("SMALL_LINKS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SMALL_LINKS_TEST_DATABASE_URL não definido; pulando teste de integração")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("abrir conexão: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Ping(); err != nil {
		t.Fatalf("ping no banco: %v", err)
	}

	return db
}
