// Package metrics define os coletores Prometheus da aplicação, registrados
// no registry default e expostos via promhttp em /metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RedirectsTotal conta redirects bem-sucedidos (HTTP 302).
	RedirectsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_redirects_total",
		Help: "Total de redirects bem-sucedidos.",
	})

	// ShortensTotal conta URLs encurtadas com sucesso (novas ou dedup).
	ShortensTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_shortens_total",
		Help: "Total de URLs encurtadas com sucesso.",
	})

	// RateLimitedTotal conta requisições rejeitadas pelo rate limiting (429).
	RateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_rate_limited_total",
		Help: "Total de requisições rejeitadas por rate limiting.",
	})

	// SafeBrowsingBlockedTotal conta URLs recusadas por serem maliciosas.
	SafeBrowsingBlockedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_safebrowsing_blocked_total",
		Help: "Total de URLs bloqueadas pela verificação Safe Browsing.",
	})

	// SafeBrowsingErrorsTotal conta falhas da verificação (fail-open).
	SafeBrowsingErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_safebrowsing_errors_total",
		Help: "Total de erros/timeouts na verificação Safe Browsing (fail-open).",
	})

	// LinksDeletedTotal conta soft deletes bem-sucedidos.
	LinksDeletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_links_deleted_total",
		Help: "Total de links desativados (soft delete) por token.",
	})

	// PasswordAttemptsTotal conta tentativas de senha em link protegido.
	PasswordAttemptsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_password_attempts_total",
		Help: "Total de tentativas de senha em links protegidos.",
	})

	// PasswordFailuresTotal conta tentativas de senha recusadas. Um salto
	// aqui sugere força bruta (ver rate limit por short_id).
	PasswordFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_password_failures_total",
		Help: "Total de tentativas de senha recusadas em links protegidos.",
	})

	// ClicksTotal conta cliques por país (ISO alpha-2 ou "unknown") e tipo
	// de dispositivo. País apenas — cidade jamais entra como label
	// (cardinalidade e privacidade).
	ClicksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "smalllinks_clicks_total",
		Help: "Total de cliques por país e dispositivo.",
	}, []string{"country", "device"})

	// GeoUnresolvedTotal conta cliques cujo IP não resolveu para um país
	// (base ausente, IP privado/inválido ou ausente da base). Um salto aqui
	// costuma indicar IP de cliente resolvido errado — ver TRUSTED_PLATFORM.
	GeoUnresolvedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smalllinks_geo_unresolved_total",
		Help: "Total de cliques sem país resolvido.",
	})

	// RequestDuration mede a latência HTTP por método, rota e status.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "smalllinks_http_request_duration_seconds",
		Help:    "Latência das requisições HTTP em segundos.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
)
