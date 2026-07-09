// Package config lê e valida as variáveis de ambiente da aplicação.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/apolinario0x21/small-links/internal/crypto"
)

var (
	ErrMissingEncryptionKey = errors.New("ENCRYPTION_KEY environment variable is not set")
	ErrMissingDatabaseURL   = errors.New("DATABASE_URL environment variable is not set")
)

type Config struct {
	EncryptionKey string
	DatabaseURL   string
	Port          string
	GinMode       string
}

func Load() (Config, error) {
	cfg := Config{
		EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		Port:          os.Getenv("PORT"),
		GinMode:       os.Getenv("GIN_MODE"),
	}

	if cfg.EncryptionKey == "" {
		return Config{}, ErrMissingEncryptionKey
	}

	if len(cfg.EncryptionKey) != crypto.KeySize {
		return Config{}, fmt.Errorf("encryption key must be %d bytes long, got %d", crypto.KeySize, len(cfg.EncryptionKey))
	}

	if cfg.DatabaseURL == "" {
		return Config{}, ErrMissingDatabaseURL
	}

	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	return cfg, nil
}
