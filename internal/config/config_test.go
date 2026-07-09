package config

import (
	"errors"
	"testing"
)

const validKey = "0123456789abcdef0123456789abcdef"

func setEnv(t *testing.T, key, dbURL, port string) {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", key)
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("PORT", port)
	t.Setenv("GIN_MODE", "")
}

func TestLoadMissingEncryptionKey(t *testing.T) {
	setEnv(t, "", "postgres://x", "")
	if _, err := Load(); !errors.Is(err, ErrMissingEncryptionKey) {
		t.Errorf("err = %v, want ErrMissingEncryptionKey", err)
	}
}

func TestLoadWrongKeySize(t *testing.T) {
	setEnv(t, "curta", "postgres://x", "")
	if _, err := Load(); err == nil {
		t.Error("Load should reject a key that is not 32 bytes long")
	}
}

func TestLoadMissingDatabaseURL(t *testing.T) {
	setEnv(t, validKey, "", "")
	if _, err := Load(); !errors.Is(err, ErrMissingDatabaseURL) {
		t.Errorf("err = %v, want ErrMissingDatabaseURL", err)
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, validKey, "postgres://x", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want default 8080", cfg.Port)
	}
}

func TestLoadExplicitPort(t *testing.T) {
	setEnv(t, validKey, "postgres://x", "9000")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "9000" {
		t.Errorf("Port = %q, want 9000", cfg.Port)
	}
}
