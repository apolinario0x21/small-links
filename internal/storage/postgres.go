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

	var expiresAt interface{}
	if data.ExpiresAt != nil {
		expiresAt = *data.ExpiresAt
	}

	insertSQL := `INSERT INTO urls (short_id, original_url, url_hash, created_at, access_count, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := p.db.ExecContext(ctx, insertSQL, data.ShortID, data.OriginalURL, data.URLHash, data.CreatedAt, data.AccessCount, expiresAt)

	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code.Name() {
		case "unique_violation":
			return ErrDuplicate
		case "string_data_right_truncation":
			return ErrValueTooLong
		}
	}

	return err
}

// FindByURLHash localiza uma URL já encurtada pelo HMAC da URL original,
// ignorando registros expirados — dedup não deve devolver um link morto.
// Registros anteriores ao backfill têm url_hash NULL e nunca casam aqui.
func (p *Postgres) FindByURLHash(ctx context.Context, urlHash string) (URLData, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var data URLData
	row := p.db.QueryRowContext(ctx, `SELECT short_id, original_url, created_at, access_count FROM urls WHERE url_hash = $1 AND (expires_at IS NULL OR expires_at > now()) ORDER BY id LIMIT 1`, urlHash)
	err := row.Scan(&data.ShortID, &data.OriginalURL, &data.CreatedAt, &data.AccessCount)
	if errors.Is(err, sql.ErrNoRows) {
		return URLData{}, ErrNotFound
	}
	return data, err
}

// FindForRedirect busca apenas as colunas necessárias ao redirect
// (sem created_at), espelhando a query original do handler.
func (p *Postgres) FindForRedirect(ctx context.Context, shortID string) (URLData, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var data URLData
	var expiresAt sql.NullTime
	row := p.db.QueryRowContext(ctx, `SELECT short_id, original_url, access_count, expires_at FROM urls WHERE short_id = $1`, shortID)
	err := row.Scan(&data.ShortID, &data.OriginalURL, &data.AccessCount, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return URLData{}, ErrNotFound
	}
	if expiresAt.Valid {
		data.ExpiresAt = &expiresAt.Time
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

// InsertClickEvent grava um evento de clique. occurred_at usa o default
// do banco (now()); referrer/user_agent vazios viram NULL para não poluir
// as agregações de analytics.
func (p *Postgres) InsertClickEvent(ctx context.Context, e ClickEvent) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	const insertSQL = `INSERT INTO click_events (short_id, referrer, user_agent, ip_hash, country, device, os, is_bot)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8)`
	_, err := p.db.ExecContext(ctx, insertSQL, e.ShortID, e.Referrer, e.UserAgent, e.IPHash, e.Country, e.Device, e.OS, e.IsBot)
	return err
}

func (p *Postgres) CountURLs(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var total int
	err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM urls`).Scan(&total)
	return total, err
}

// ClickStats devolve total de cliques, cliques por dia nos últimos 30 dias
// e os 5 referrers mais frequentes de um short link.
func (p *Postgres) ClickStats(ctx context.Context, shortID string) (ClickStats, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	stats := ClickStats{
		ClicksPerDay: []DailyClicks{},
		TopReferrers: []ReferrerCount{},
		TopCountries: []CountryCount{},
		Devices:      []DeviceCount{},
	}

	err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM click_events WHERE short_id = $1 AND NOT is_bot`, shortID,
	).Scan(&stats.TotalClicks)
	if err != nil {
		return ClickStats{}, err
	}

	dayRows, err := p.db.QueryContext(ctx,
		`SELECT date_trunc('day', occurred_at) AS day, COUNT(*)
		 FROM click_events
		 WHERE short_id = $1 AND NOT is_bot AND occurred_at >= now() - interval '30 days'
		 GROUP BY day
		 ORDER BY day`, shortID)
	if err != nil {
		return ClickStats{}, err
	}
	defer dayRows.Close()

	for dayRows.Next() {
		var day time.Time
		var count int
		if err := dayRows.Scan(&day, &count); err != nil {
			return ClickStats{}, err
		}
		stats.ClicksPerDay = append(stats.ClicksPerDay, DailyClicks{
			Day:   day.Format("2006-01-02"),
			Count: count,
		})
	}
	if err := dayRows.Err(); err != nil {
		return ClickStats{}, err
	}

	refRows, err := p.db.QueryContext(ctx,
		`SELECT referrer, COUNT(*) AS n
		 FROM click_events
		 WHERE short_id = $1 AND NOT is_bot AND referrer IS NOT NULL
		 GROUP BY referrer
		 ORDER BY n DESC, referrer
		 LIMIT 5`, shortID)
	if err != nil {
		return ClickStats{}, err
	}
	defer refRows.Close()

	for refRows.Next() {
		var ref ReferrerCount
		if err := refRows.Scan(&ref.Referrer, &ref.Count); err != nil {
			return ClickStats{}, err
		}
		stats.TopReferrers = append(stats.TopReferrers, ref)
	}
	if err := refRows.Err(); err != nil {
		return ClickStats{}, err
	}

	countryRows, err := p.db.QueryContext(ctx,
		`SELECT country, COUNT(*) AS n
		 FROM click_events
		 WHERE short_id = $1 AND NOT is_bot AND country IS NOT NULL
		 GROUP BY country
		 ORDER BY n DESC, country
		 LIMIT 5`, shortID)
	if err != nil {
		return ClickStats{}, err
	}
	defer countryRows.Close()

	for countryRows.Next() {
		var cc CountryCount
		if err := countryRows.Scan(&cc.Country, &cc.Count); err != nil {
			return ClickStats{}, err
		}
		stats.TopCountries = append(stats.TopCountries, cc)
	}
	if err := countryRows.Err(); err != nil {
		return ClickStats{}, err
	}

	deviceRows, err := p.db.QueryContext(ctx,
		`SELECT device, COUNT(*) AS n
		 FROM click_events
		 WHERE short_id = $1 AND NOT is_bot AND device IS NOT NULL
		 GROUP BY device
		 ORDER BY n DESC, device`, shortID)
	if err != nil {
		return ClickStats{}, err
	}
	defer deviceRows.Close()

	for deviceRows.Next() {
		var dc DeviceCount
		if err := deviceRows.Scan(&dc.Device, &dc.Count); err != nil {
			return ClickStats{}, err
		}
		stats.Devices = append(stats.Devices, dc)
	}
	if err := deviceRows.Err(); err != nil {
		return ClickStats{}, err
	}

	return stats, nil
}
