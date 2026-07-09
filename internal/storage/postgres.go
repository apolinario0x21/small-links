package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
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

// Migrate cria a tabela urls caso ainda não exista.
func Migrate(db *sql.DB) error {
	const createTableSQL = `
	CREATE TABLE IF NOT EXISTS urls (
		id SERIAL PRIMARY KEY,
		short_id VARCHAR(6) UNIQUE NOT NULL,
		original_url TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL,
		access_count INT NOT NULL DEFAULT 0
	);`

	if _, err := db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create 'urls' table: %w", err)
	}

	return nil
}

func (p *Postgres) ShortIDExists(ctx context.Context, shortID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM urls WHERE short_id = $1)"
	err := p.db.QueryRowContext(ctx, query, shortID).Scan(&exists)
	return exists, err
}

func (p *Postgres) Insert(ctx context.Context, data URLData) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	insertSQL := `INSERT INTO urls (short_id, original_url, created_at, access_count) VALUES ($1, $2, $3, $4)`
	_, err := p.db.ExecContext(ctx, insertSQL, data.ShortID, data.OriginalURL, data.CreatedAt, data.AccessCount)
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
