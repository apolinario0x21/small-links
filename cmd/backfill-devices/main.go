// One-off: retroage device/os/is_bot nos eventos de clique existentes a
// partir do user_agent gravado. Idempotente: só processa linhas com
// user_agent preenchido e device NULL. Geolocalização não é retroagível
// (o IP nunca foi persistido — apenas o hash).
package main

import (
	"database/sql"
	"log/slog"
	"os"

	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/storage"
)

const progressEvery = 500

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := run(logger); err != nil {
		logger.Error("backfill failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := storage.Connect(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, user_agent FROM click_events WHERE user_agent IS NOT NULL AND device IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type record struct {
		id int64
		ua string
	}
	var records []record
	for rows.Next() {
		var r record
		if err := rows.Scan(&r.id, &r.ua); err != nil {
			return err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	logger.Info("starting device backfill", "pending_rows", len(records))

	processed, failed := 0, 0
	for _, r := range records {
		if err := backfillRow(db, r.id, r.ua); err != nil {
			logger.Error("failed to backfill row", "id", r.id, "error", err)
			failed++
			continue
		}
		processed++
		if processed%progressEvery == 0 {
			logger.Info("backfill progress", "processed", processed, "total", len(records))
		}
	}

	logger.Info("backfill finished", "processed", processed, "failed", failed, "total", len(records))
	return nil
}

func backfillRow(db *sql.DB, id int64, ua string) error {
	device, osName, isBot := analytics.ParseDevice(ua)
	_, err := db.Exec(
		`UPDATE click_events SET device = NULLIF($1, ''), os = NULLIF($2, ''), is_bot = $3 WHERE id = $4 AND device IS NULL`,
		device, osName, isBot, id,
	)
	return err
}
