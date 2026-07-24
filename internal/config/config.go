// Package config lê e valida as variáveis de ambiente da aplicação.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/apolinario0x21/small-links/internal/crypto"
)

var (
	ErrMissingEncryptionKey = errors.New("ENCRYPTION_KEY environment variable is not set")
	ErrMissingDatabaseURL   = errors.New("DATABASE_URL environment variable is not set")
)

type Config struct {
	EncryptionKey      string
	DatabaseURL        string
	Port               string
	GinMode            string
	SwaggerEnabled     bool
	SafeBrowsingAPIKey string
	GeoIPDBPath        string
	TrustedPlatform    string
	// CORSAllowedOrigins é a allowlist de origens autorizadas a chamar a API
	// via browser. Vazia = só a própria origem da aplicação (ver
	// internal/http.corsMiddleware).
	CORSAllowedOrigins []string
}

// PlatformCloudflare habilita a leitura do IP do cliente a partir do header
// CF-Connecting-IP (ver internal/http.Server.Router).
const PlatformCloudflare = "cloudflare"

// parseOrigins quebra a lista separada por vírgula, descartando entradas
// vazias e espaços. O curinga "*" não é aceito: reabrir a API para qualquer
// origem é justamente o que a allowlist existe para impedir.
func parseOrigins(raw string) []string {
	var origins []string
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(part)
		if origin == "" || origin == "*" {
			continue
		}
		origins = append(origins, origin)
	}
	return origins
}

func Load() (Config, error) {
	cfg := Config{
		EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		Port:          os.Getenv("PORT"),
		GinMode:       os.Getenv("GIN_MODE"),
		// A UI do Swagger fica ligada por padrão; defina SWAGGER_ENABLED=false
		// para desabilitá-la (ex.: em produção).
		SwaggerEnabled: os.Getenv("SWAGGER_ENABLED") != "false",
		// Vazia = verificação de URL maliciosa (Safe Browsing) desabilitada.
		SafeBrowsingAPIKey: os.Getenv("SAFE_BROWSING_API_KEY"),
		GeoIPDBPath:        os.Getenv("GEOIP_DB_PATH"),
		// Vazia = confia apenas nos proxies de faixa privada (comportamento
		// padrão, seguro em qualquer topologia). "cloudflare" só é válido
		// quando TODO o tráfego externo passa obrigatoriamente pela borda
		// Cloudflare (caso do Render) — ver internal/http.Server.Router.
		TrustedPlatform: strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTED_PLATFORM"))),
		// Lista separada por vírgula, ex.:
		// "https://app.exemplo.com,https://admin.exemplo.com".
		CORSAllowedOrigins: parseOrigins(os.Getenv("CORS_ALLOWED_ORIGINS")),
	}

	if cfg.GeoIPDBPath == "" {
		// Caminho onde o Dockerfile deposita a base DB-IP Lite.
		cfg.GeoIPDBPath = "/app/dbip-country-lite.mmdb"
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
