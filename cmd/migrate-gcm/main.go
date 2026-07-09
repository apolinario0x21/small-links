// Comando de backfill: percorre todas as linhas com url_hash NULL,
// decifra a URL (GCM ou CTR legado), preenche url_hash e re-cifra em GCM.
//
// Idempotente: linhas já processadas têm url_hash preenchido e são
// ignoradas em execuções seguintes. Requer ENCRYPTION_KEY e DATABASE_URL.
package main

import (
	"database/sql"
	"log/slog"
	"os"

	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	"github.com/apolinario0x21/small-links/internal/storage"
)

const progressEvery = 100

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

	cipher, err := crypto.New([]byte(cfg.EncryptionKey))
	if err != nil {
		return err
	}

	db, err := storage.Connect(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := storage.Migrate(db); err != nil {
		return err
	}

	var pending int
	if err := db.QueryRow(`SELECT COUNT(*) FROM urls WHERE url_hash IS NULL`).Scan(&pending); err != nil {
		return err
	}
	logger.Info("starting backfill", "pending_rows", pending)

	rows, err := db.Query(`SELECT id, original_url FROM urls WHERE url_hash IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type record struct {
		id        int
		encrypted string
	}
	var records []record
	for rows.Next() {
		var r record
		if err := rows.Scan(&r.id, &r.encrypted); err != nil {
			return err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	processed, failed := 0, 0
	for _, r := range records {
		if err := backfillRow(db, cipher, r.id, r.encrypted); err != nil {
			// Não interrompe o backfill: a linha permanece com url_hash
			// NULL e volta a ser tentada na próxima execução.
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

func backfillRow(db *sql.DB, cipher *crypto.Cipher, id int, encrypted string) error {
	plainURL, err := cipher.Decrypt(encrypted)
	if err != nil {
		return err
	}

	reEncrypted, err := cipher.Encrypt(plainURL)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		`UPDATE urls SET original_url = $1, url_hash = $2 WHERE id = $3 AND url_hash IS NULL`,
		reEncrypted, cipher.Hash(plainURL), id,
	)
	return err
}
