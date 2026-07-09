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

	// RequestDuration mede a latência HTTP por método, rota e status.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "smalllinks_http_request_duration_seconds",
		Help:    "Latência das requisições HTTP em segundos.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
)
