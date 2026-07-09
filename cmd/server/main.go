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

	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	httpapi "github.com/apolinario0x21/small-links/internal/http"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

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

	server := httpapi.New(storage.NewPostgres(db), cipher, logger)

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

	return srv.Shutdown(shutdownCtx)
}
