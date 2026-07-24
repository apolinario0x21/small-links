package storage_test

import (
	"context"
	"testing"

	"github.com/apolinario0x21/small-links/internal/storage"
)

// TestClickStatsAggregationsShareExclusionCriteria valida, contra um Postgres
// real, que todas as agregações do payload de stats aplicam o mesmo critério de
// exclusão: bots (is_bot) ficam de fora de tudo e cliques não classificados
// entram como "unknown". A invariante central é
// soma(devices) == soma(top_countries) == total_clicks.
//
// Gated por SMALL_LINKS_TEST_DATABASE_URL; sem a env var o teste é pulado para
// não quebrar o CI que roda apenas `go test` sem banco.
func TestClickStatsAggregationsShareExclusionCriteria(t *testing.T) {
	db := openTestDB(t)

	if err := storage.Migrate(db); err != nil {
		t.Fatalf("aplicar migrations: %v", err)
	}

	const shortID = "statsInvariant"
	if _, err := db.Exec(`DELETE FROM click_events WHERE short_id = $1`, shortID); err != nil {
		t.Fatalf("limpar click_events: %v", err)
	}

	repo := storage.NewPostgres(db)
	ctx := context.Background()

	// Conjunto misto: país+device classificados, país/device vazios (viram
	// "unknown") e bots (devem ser excluídos de todas as agregações).
	events := []storage.ClickEvent{
		{ShortID: shortID, Country: "BR", Device: "mobile"},
		{ShortID: shortID, Country: "BR", Device: "desktop"},
		{ShortID: shortID, Country: "US", Device: "mobile"},
		{ShortID: shortID, Country: "", Device: "tablet"},                // país unknown
		{ShortID: shortID, Country: "PT", Device: ""},                    // device unknown
		{ShortID: shortID, Country: "", Device: ""},                      // ambos unknown
		{ShortID: shortID, Country: "BR", Device: "mobile", IsBot: true}, // excluído
		{ShortID: shortID, Country: "", Device: "", IsBot: true},         // excluído
	}
	for _, e := range events {
		if err := repo.InsertClickEvent(ctx, e); err != nil {
			t.Fatalf("inserir evento: %v", err)
		}
	}

	const wantTotal = 6 // 8 eventos - 2 bots

	stats, err := repo.ClickStats(ctx, shortID)
	if err != nil {
		t.Fatalf("ClickStats: %v", err)
	}

	if stats.TotalClicks != wantTotal {
		t.Errorf("total_clicks = %d, esperado %d", stats.TotalClicks, wantTotal)
	}

	countrySum := 0
	countryUnknown := false
	for _, c := range stats.TopCountries {
		countrySum += c.Count
		if c.Country == "unknown" {
			countryUnknown = true
		}
	}
	deviceSum := 0
	deviceUnknown := false
	for _, d := range stats.Devices {
		deviceSum += d.Count
		if d.Device == "unknown" {
			deviceUnknown = true
		}
	}

	// Invariante: mesmo critério de exclusão em todo o payload.
	if countrySum != stats.TotalClicks || deviceSum != stats.TotalClicks {
		t.Errorf("somas divergem: total=%d, top_countries=%d, devices=%d",
			stats.TotalClicks, countrySum, deviceSum)
	}

	if !countryUnknown {
		t.Error("esperava categoria \"unknown\" em top_countries")
	}
	if !deviceUnknown {
		t.Error("esperava categoria \"unknown\" em devices")
	}
}
