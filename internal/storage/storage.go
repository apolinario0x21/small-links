// Package storage define o repositório de URLs e sua implementação PostgreSQL.
package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound indica que não existe URL com o short_id consultado.
var ErrNotFound = errors.New("short URL not found")

// ErrDuplicate indica violação da constraint UNIQUE de short_id no insert.
var ErrDuplicate = errors.New("short_id already exists")

type URLData struct {
	ID          int
	ShortID     string
	OriginalURL string
	URLHash     string
	CreatedAt   time.Time
	AccessCount int
	// ExpiresAt nil = link permanente; caso contrário, expira na data.
	ExpiresAt *time.Time
}

// ClickEvent é um evento de acesso a um short link, gravado de forma
// assíncrona. Referrer e UserAgent podem ser vazios; IPHash é o HMAC do IP.
type ClickEvent struct {
	ShortID   string
	Referrer  string
	UserAgent string
	IPHash    string
}

// DailyClicks agrega cliques por dia (Day no formato ISO YYYY-MM-DD).
type DailyClicks struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

// ReferrerCount agrega cliques por referrer.
type ReferrerCount struct {
	Referrer string `json:"referrer"`
	Count    int    `json:"count"`
}

// ClickStats reúne as métricas de acesso expostas no endpoint de stats.
// As fatias são sempre não-nulas para serializar como [] e não null.
type ClickStats struct {
	TotalClicks  int             `json:"total_clicks"`
	ClicksPerDay []DailyClicks   `json:"clicks_per_day"`
	TopReferrers []ReferrerCount `json:"top_referrers"`
}

type Repository interface {
	Insert(ctx context.Context, data URLData) error
	FindByURLHash(ctx context.Context, urlHash string) (URLData, error)
	FindForRedirect(ctx context.Context, shortID string) (URLData, error)
	FindByShortID(ctx context.Context, shortID string) (URLData, error)
	IncrementAccessCount(ctx context.Context, shortID string) error
	CountURLs(ctx context.Context) (int, error)
	InsertClickEvent(ctx context.Context, e ClickEvent) error
	ClickStats(ctx context.Context, shortID string) (ClickStats, error)
}
