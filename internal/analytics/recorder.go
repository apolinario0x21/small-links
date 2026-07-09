// Package analytics registra eventos de clique de forma assíncrona, sem
// bloquear o caminho quente do redirect.
package analytics

import (
	"context"
	"log/slog"
	"time"

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

// Recorder enfileira eventos num canal buffered e os grava em background.
// Perder eventos sob carga é aceitável; atrasar o redirect não é.
type Recorder struct {
	events chan storage.ClickEvent
	store  EventInserter
	logger *slog.Logger
	done   chan struct{}
}

func NewRecorder(store EventInserter, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Recorder{
		events: make(chan storage.ClickEvent, bufferSize),
		store:  store,
		logger: logger,
		done:   make(chan struct{}),
	}
	go r.worker()
	return r
}

// Record enfileira um evento sem bloquear. Se o buffer estiver cheio, o
// evento é descartado com log em nível warn.
func (r *Recorder) Record(e storage.ClickEvent) {
	select {
	case r.events <- e:
	default:
		r.logger.Warn("click event buffer full, dropping event", "short_id", e.ShortID)
	}
}

func (r *Recorder) worker() {
	defer close(r.done)
	for e := range r.events {
		r.persist(e)
	}
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
