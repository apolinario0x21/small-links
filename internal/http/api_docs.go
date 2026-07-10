package http

// Modelos usados apenas na documentação Swagger/OpenAPI. Os handlers
// serializam via gin.H; estas structs descrevem o formato das respostas
// para a UI, sem alterar o comportamento em runtime.

// ErrorResponse é o corpo padrão de erro.
type ErrorResponse struct {
	Error string `json:"error" example:"Short URL not found"`
}

// ShortenResponse é a resposta de criação de short link.
type ShortenResponse struct {
	ShortID     string `json:"short_id" example:"promo"`
	ShortURL    string `json:"short_url" example:"https://exemplo.com/promo"`
	OriginalURL string `json:"original_url" example:"https://www.exemplo.com/pagina"`
	CreatedAt   string `json:"created_at" example:"2026-07-10T12:00:00Z"`
	ExpiresAt   string `json:"expires_at,omitempty" example:"2026-08-09T12:00:00Z"`
	Existing    bool   `json:"existing,omitempty" example:"false"`
}

// DailyClicksDoc agrega cliques por dia (documentação).
type DailyClicksDoc struct {
	Day   string `json:"day" example:"2026-07-10"`
	Count int    `json:"count" example:"12"`
}

// ReferrerCountDoc agrega cliques por referrer (documentação).
type ReferrerCountDoc struct {
	Referrer string `json:"referrer" example:"https://news.exemplo.com"`
	Count    int    `json:"count" example:"20"`
}

// StatsResponse é a resposta do endpoint de estatísticas.
type StatsResponse struct {
	ShortID      string             `json:"short_id" example:"promo"`
	OriginalURL  string             `json:"original_url" example:"https://www.exemplo.com/pagina"`
	CreatedAt    string             `json:"created_at" example:"2026-07-10T12:00:00Z"`
	AccessCount  int                `json:"access_count" example:"42"`
	TotalClicks  int                `json:"total_clicks" example:"42"`
	ClicksPerDay []DailyClicksDoc   `json:"clicks_per_day"`
	TopReferrers []ReferrerCountDoc `json:"top_referrers"`
}

// HealthResponse é a resposta do health check.
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	TotalURLs int    `json:"total_urls" example:"123"`
	Timestamp string `json:"timestamp" example:"2026-07-10T12:00:00Z"`
}
