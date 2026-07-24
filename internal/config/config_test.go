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

func TestLoadCORSAllowedOrigins(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"vazia", "", nil},
		{"uma origem", "https://app.exemplo.com", []string{"https://app.exemplo.com"}},
		{
			"várias com espaços",
			" https://a.exemplo.com , https://b.exemplo.com ",
			[]string{"https://a.exemplo.com", "https://b.exemplo.com"},
		},
		// O curinga é ignorado: reabrir para qualquer origem é exatamente o
		// que a allowlist existe para impedir.
		{"curinga ignorado", "*", nil},
		{"entradas vazias descartadas", "https://a.exemplo.com,,", []string{"https://a.exemplo.com"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, validKey, "postgres://x", "")
			t.Setenv("CORS_ALLOWED_ORIGINS", tc.raw)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if len(cfg.CORSAllowedOrigins) != len(tc.want) {
				t.Fatalf("CORSAllowedOrigins = %v, want %v", cfg.CORSAllowedOrigins, tc.want)
			}
			for i, want := range tc.want {
				if cfg.CORSAllowedOrigins[i] != want {
					t.Errorf("CORSAllowedOrigins[%d] = %q, want %q", i, cfg.CORSAllowedOrigins[i], want)
				}
			}
		})
	}
}
