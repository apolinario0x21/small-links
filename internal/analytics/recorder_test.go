package analytics

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/apolinario0x21/small-links/internal/storage"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// collectingStore guarda os eventos gravados de forma thread-safe.
type collectingStore struct {
	mu     sync.Mutex
	events []storage.ClickEvent
}

func (s *collectingStore) InsertClickEvent(_ context.Context, e storage.ClickEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *collectingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestRecorderPersistsAndFlushesOnClose(t *testing.T) {
	store := &collectingStore{}
	r := NewRecorder(store, quietLogger())

	for i := 0; i < 3; i++ {
		r.Record(storage.ClickEvent{ShortID: "abc123"})
	}
	r.Close() // deve drenar o buffer antes de retornar

	if got := store.count(); got != 3 {
		t.Errorf("persisted = %d, want 3 after flush on Close", got)
	}
}

// blockingStore trava o primeiro insert até `release` fechar, sinalizando
// em `started` que o worker já retirou o primeiro evento do buffer.
type blockingStore struct {
	mu      sync.Mutex
	count   int
	started chan struct{}
	release chan struct{}
}

func (s *blockingStore) InsertClickEvent(_ context.Context, _ storage.ClickEvent) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	return nil
}

func TestRecorderDropsWhenBufferFull(t *testing.T) {
	store := &blockingStore{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	r := NewRecorder(store, quietLogger())

	// Primeiro evento: o worker o retira e bloqueia dentro do insert.
	r.Record(storage.ClickEvent{ShortID: "first"})
	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never started processing the first event")
	}

	// Com o worker travado, o buffer (cap bufferSize) enche exatamente.
	for i := 0; i < bufferSize; i++ {
		r.Record(storage.ClickEvent{ShortID: "buffered"})
	}
	// Estes excedem a capacidade e são descartados.
	const extra = 100
	for i := 0; i < extra; i++ {
		r.Record(storage.ClickEvent{ShortID: "dropped"})
	}

	close(store.release) // libera os inserts
	r.Close()            // drena e aguarda o worker

	store.mu.Lock()
	got := store.count
	store.mu.Unlock()

	if want := bufferSize + 1; got != want {
		t.Errorf("persisted = %d, want %d (%d dropped)", got, want, extra)
	}
}
