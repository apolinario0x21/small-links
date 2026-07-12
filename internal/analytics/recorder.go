// Package analytics registra eventos de clique de forma assíncrona, sem
// bloquear o caminho quente do redirect.
package analytics

import (
	"context"
	"log/slog"
	"time"

	"github.com/apolinario0x21/small-links/internal/metrics"
	"github.com/apolinario0x21/small-links/internal/storage"
)

const (
	// bufferSize é a capacidade do canal de eventos pendentes.
	bufferSize = 1000
	// insertTimeout limita cada gravação no banco feita pelo worker.
	insertTimeout = 5 * time.Second
)

// EventInserter é a dependência de persistência do Recorder (satisfeita
// por *storage.Postgres).
type EventInserter interface {
	InsertClickEvent(ctx context.Context, e storage.ClickEvent) error
}

// GeoResolver resolve o país de um IP (satisfeito por *geo.Resolver).
// Nil = geolocalização desabilitada; "" = país desconhecido/IP privado.
type GeoResolver interface {
	CountryCode(ip string) string
}

// IPHasher gera o hash irreversível do IP (satisfeito por *crypto.Cipher).
type IPHasher interface {
	Hash(s string) string
}

// Click é o evento bruto publicado pelo handler de redirect. O campo IP é
// transitório: usado apenas para resolver o país e gerar o ip_hash dentro
// do processo — nunca é persistido nem sai da aplicação.
type Click struct {
	ShortID   string
	Referrer  string
	UserAgent string
	IP        string
}

// Recorder enfileira eventos num canal buffered e os enriquece/grava em
// background. Perder eventos sob carga é aceitável; atrasar o redirect não.
type Recorder struct {
	events chan Click
	store  EventInserter
	geo    GeoResolver
	hasher IPHasher
	logger *slog.Logger
	done   chan struct{}
}

func NewRecorder(store EventInserter, geo GeoResolver, hasher IPHasher, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Recorder{
		events: make(chan Click, bufferSize),
		store:  store,
		geo:    geo,
		hasher: hasher,
		logger: logger,
		done:   make(chan struct{}),
	}
	go r.worker()
	return r
}

// Record enfileira um evento sem bloquear. Se o buffer estiver cheio, o
// evento é descartado com log em nível warn.
func (r *Recorder) Record(c Click) {
	select {
	case r.events <- c:
	default:
		r.logger.Warn("click event buffer full, dropping event", "short_id", c.ShortID)
	}
}

func (r *Recorder) worker() {
	defer close(r.done)
	for c := range r.events {
		r.persist(r.enrich(c))
	}
}

// enrich resolve o país ANTES de gerar o ip_hash e descarta o IP em claro;
// classifica o dispositivo a partir do user-agent.
func (r *Recorder) enrich(c Click) storage.ClickEvent {
	e := storage.ClickEvent{
		ShortID:   c.ShortID,
		Referrer:  c.Referrer,
		UserAgent: c.UserAgent,
	}

	if r.geo != nil {
		e.Country = r.geo.CountryCode(c.IP)
	}
	if r.hasher != nil && c.IP != "" {
		e.IPHash = r.hasher.Hash(c.IP)
	}
	e.Device, e.OS, e.IsBot = ParseDevice(c.UserAgent)

	country, device := e.Country, e.Device
	if country == "" {
		country = "unknown"
		metrics.GeoUnresolvedTotal.Inc()
	}
	if device == "" {
		device = "unknown"
	}
	metrics.ClicksTotal.WithLabelValues(country, device).Inc()

	return e
}

func (r *Recorder) persist(e storage.ClickEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), insertTimeout)
	defer cancel()

	if err := r.store.InsertClickEvent(ctx, e); err != nil {
		r.logger.Error("failed to insert click event", "error", err, "short_id", e.ShortID)
	}
}

// Close fecha o canal, drena os eventos ainda pendentes e aguarda o worker
// terminar. Chamado no graceful shutdown, após o servidor HTTP parar de
// aceitar novas requisições (nenhum Record concorrente é esperado aqui).
func (r *Recorder) Close() {
	close(r.events)
	<-r.done
}
