package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"time"

	"github.com/apolinario0x21/small-links/migrations"
	"github.com/lib/pq"
)

const queryTimeout = 5 * time.Second

// Postgres implementa Repository sobre um *sql.DB PostgreSQL.
type Postgres struct {
	db *sql.DB
}

func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

// Connect abre a conexão e tenta o ping até 5 vezes antes de desistir.
func Connect(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open a DB connection: %w", err)
	}

	for i := 0; i < 5; i++ {
		err = db.Ping()
		if err == nil {
			return db, nil
		}
		log.Printf("Unsuccessful database connection, retrying in 5 seconds... (%d/5)", i+1)
		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("several unsuccessful connection attempts: %w", err)
}

// Migrate aplica, em ordem, os arquivos SQL embutidos em migrations/.
// Todos os statements são idempotentes (CREATE TABLE IF NOT EXISTS).
func Migrate(db *sql.DB) error {
	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return fmt.Errorf("failed to list migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", name, err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", name, err)
		}
	}

	return nil
}

func (p *Postgres) Insert(ctx context.Context, data URLData) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	insertSQL := `INSERT INTO urls (short_id, original_url, created_at, access_count) VALUES ($1, $2, $3, $4)`
	_, err := p.db.ExecContext(ctx, insertSQL, data.ShortID, data.OriginalURL, data.CreatedAt, data.AccessCount)

	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code.Name() == "unique_violation" {
		return ErrDuplicate
	}

	return err
}

// FindForRedirect busca apenas as colunas necessárias ao redirect
// (sem created_at), espelhando a query original do handler.
func (p *Postgres) FindForRedirect(ctx context.Context, shortID string) (URLData, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var data URLData
	row := p.db.QueryRowContext(ctx, `SELECT short_id, original_url, access_count FROM urls WHERE short_id = $1`, shortID)
	err := row.Scan(&data.ShortID, &data.OriginalURL, &data.AccessCount)
	if errors.Is(err, sql.ErrNoRows) {
		return URLData{}, ErrNotFound
	}
	return data, err
}

func (p *Postgres) FindByShortID(ctx context.Context, shortID string) (URLData, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var data URLData
	row := p.db.QueryRowContext(ctx, `SELECT short_id, original_url, created_at, access_count FROM urls WHERE short_id = $1`, shortID)
	err := row.Scan(&data.ShortID, &data.OriginalURL, &data.CreatedAt, &data.AccessCount)
	if errors.Is(err, sql.ErrNoRows) {
		return URLData{}, ErrNotFound
	}
	return data, err
}

func (p *Postgres) IncrementAccessCount(ctx context.Context, shortID string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	updateSQL := `UPDATE urls SET access_count = access_count + 1 WHERE short_id = $1`
	_, err := p.db.ExecContext(ctx, updateSQL, shortID)
	return err
}

func (p *Postgres) CountURLs(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var total int
	err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM urls`).Scan(&total)
	return total, err
}
