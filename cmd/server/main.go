package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apolinario0x21/small-links/internal/analytics"
	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	httpapi "github.com/apolinario0x21/small-links/internal/http"
	"github.com/apolinario0x21/small-links/internal/safebrowsing"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"

	// Registra a especificação OpenAPI gerada por swag (init()).
	_ "github.com/apolinario0x21/small-links/docs"
)

// @title           Small Links API
// @version         1.0
// @description     Encurtador de URLs em Go com AES-256-GCM, deduplicação por HMAC, alias customizado, TTL/expiração, QR code, analytics de clique e métricas Prometheus.
// @description     As URLs originais são cifradas em repouso; o IP dos acessos é gravado apenas como HMAC (LGPD).
// @contact.name    Small Links
// @license.name    MIT
// @license.url     https://opensource.org/licenses/MIT
// @BasePath        /
// @schemes         http https
func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

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
	logger.Info("successfully connected to the database")

	if err := storage.Migrate(db); err != nil {
		return err
	}
	logger.Info("database migration completed")

	pg := storage.NewPostgres(db)
	recorder := analytics.NewRecorder(pg, logger)

	// Sem chave, a verificação de URL maliciosa fica desabilitada (checker nil).
	var checker httpapi.URLChecker
	if cfg.SafeBrowsingAPIKey != "" {
		checker = safebrowsing.New(cfg.SafeBrowsingAPIKey)
	} else {
		logger.Warn("SAFE_BROWSING_API_KEY não definida; verificação de URL maliciosa desabilitada")
	}

	server := httpapi.New(pg, cipher, recorder, checker, logger, cfg.SwaggerEnabled)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: server.Router(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = srv.Shutdown(shutdownCtx)

	// Drena os eventos de clique pendentes só depois que o servidor parou
	// de aceitar requisições (nenhum Record concorrente resta). Roda antes
	// do db.Close() adiado, que ainda é necessário para o flush.
	recorder.Close()

	return err
}
