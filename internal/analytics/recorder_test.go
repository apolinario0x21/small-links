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
	r := NewRecorder(store, nil, nil, quietLogger())

	for i := 0; i < 3; i++ {
		r.Record(Click{ShortID: "abc123"})
	}
	r.Close() // deve drenar o buffer antes de retornar

	if got := store.count(); got != 3 {
		t.Errorf("persisted = %d, want 3 after flush on Close", got)
	}
}

// fakeGeo devolve país fixo para IPs públicos, "" para privados.
type fakeGeo struct{ country string }

func (f fakeGeo) CountryCode(ip string) string {
	if ip == "10.0.0.1" || ip == "" {
		return ""
	}
	return f.country
}

// fakeHasher marca o valor para inspeção no teste.
type fakeHasher struct{}

func (fakeHasher) Hash(s string) string { return "hash(" + s + ")" }

func TestRecorderEnrichesEvents(t *testing.T) {
	store := &collectingStore{}
	r := NewRecorder(store, fakeGeo{country: "BR"}, fakeHasher{}, quietLogger())

	const iphoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
	r.Record(Click{ShortID: "abc123", UserAgent: iphoneUA, IP: "203.0.113.5", Referrer: "https://x.example"})
	r.Close()

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 1 {
		t.Fatalf("persisted = %d, want 1", len(store.events))
	}
	e := store.events[0]
	if e.Country != "BR" {
		t.Errorf("Country = %q, want BR", e.Country)
	}
	if e.Device != "mobile" {
		t.Errorf("Device = %q, want mobile", e.Device)
	}
	if e.IsBot {
		t.Error("iPhone não é bot")
	}
	if e.IPHash != "hash(203.0.113.5)" {
		t.Errorf("IPHash = %q — o hash deve ser gerado a partir do IP", e.IPHash)
	}
	if e.OS == "" {
		t.Error("OS não deveria ser vazio para UA de iPhone")
	}
}

func TestRecorderEnrichBotAndPrivateIP(t *testing.T) {
	store := &collectingStore{}
	r := NewRecorder(store, fakeGeo{country: "BR"}, fakeHasher{}, quietLogger())

	r.Record(Click{
		ShortID:   "abc123",
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		IP:        "10.0.0.1", // privado → country vazio (NULL)
	})
	r.Close()

	store.mu.Lock()
	defer store.mu.Unlock()
	e := store.events[0]
	if !e.IsBot || e.Device != "bot" {
		t.Errorf("Googlebot deve marcar is_bot/device=bot, got %v/%q", e.IsBot, e.Device)
	}
	if e.Country != "" {
		t.Errorf("IP privado deve deixar Country vazio, got %q", e.Country)
	}
}

func TestRecorderNilGeoAndHasherAreSafe(t *testing.T) {
	store := &collectingStore{}
	r := NewRecorder(store, nil, nil, quietLogger())

	r.Record(Click{ShortID: "abc123", IP: "203.0.113.5"})
	r.Close()

	store.mu.Lock()
	defer store.mu.Unlock()
	e := store.events[0]
	if e.Country != "" || e.IPHash != "" {
		t.Errorf("sem geo/hasher os campos devem ficar vazios, got %q/%q", e.Country, e.IPHash)
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
	r := NewRecorder(store, nil, nil, quietLogger())

	// Primeiro evento: o worker o retira e bloqueia dentro do insert.
	r.Record(Click{ShortID: "first"})
	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never started processing the first event")
	}

	// Com o worker travado, o buffer (cap bufferSize) enche exatamente.
	for i := 0; i < bufferSize; i++ {
		r.Record(Click{ShortID: "buffered"})
	}
	// Estes excedem a capacidade e são descartados.
	const extra = 100
	for i := 0; i < extra; i++ {
		r.Record(Click{ShortID: "dropped"})
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
