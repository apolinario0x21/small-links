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

// ErrValueTooLong indica que um valor excede o limite da coluna
// (string_data_right_truncation). Sinaliza divergência entre a validação
// da aplicação e o schema; o handler deve responder 400, não 500.
var ErrValueTooLong = errors.New("value exceeds column size")

type URLData struct {
	ID          int
	ShortID     string
	OriginalURL string
	URLHash     string
	CreatedAt   time.Time
	AccessCount int
	// ExpiresAt nil = link permanente; caso contrário, expira na data.
	ExpiresAt *time.Time
	// ManagementTokenHash é o SHA-256 do token de gerenciamento; vazio =
	// link não-gerenciável (criado antes da feature). DeletedAt nil = ativo;
	// caso contrário, soft-deletado.
	ManagementTokenHash string
	DeletedAt           *time.Time
	// PasswordHash é o bcrypt da senha de acesso; vazio = link público. A
	// senha em claro nunca é persistida nem devolvida em resposta alguma.
	PasswordHash string
}

// ClickEvent é um evento de acesso a um short link, gravado de forma
// assíncrona. Referrer e UserAgent podem ser vazios; IPHash é o HMAC do IP.
// Country (ISO 3166-1 alpha-2), Device, OS e IsBot são enriquecidos pelo
// Recorder no momento do clique; campos vazios viram NULL.
type ClickEvent struct {
	ShortID   string
	Referrer  string
	UserAgent string
	IPHash    string
	Country   string
	Device    string
	OS        string
	IsBot     bool
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

// CountryCount agrega cliques por país (ISO 3166-1 alpha-2).
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// DeviceCount agrega cliques por tipo de dispositivo.
type DeviceCount struct {
	Device string `json:"device"`
	Count  int    `json:"count"`
}

// ClickStats reúne as métricas de acesso expostas no endpoint de stats.
// As fatias são sempre não-nulas para serializar como [] e não null.
// Todas as agregações excluem cliques de bots (is_bot = true).
type ClickStats struct {
	TotalClicks  int             `json:"total_clicks"`
	ClicksPerDay []DailyClicks   `json:"clicks_per_day"`
	TopReferrers []ReferrerCount `json:"top_referrers"`
	TopCountries []CountryCount  `json:"top_countries"`
	Devices      []DeviceCount   `json:"devices"`
}

type Repository interface {
	Insert(ctx context.Context, data URLData) error
	// FindByURLHash localiza um link reaproveitável pelo HMAC da URL.
	// Ignora expirados, deletados e PROTEGIDOS POR SENHA — quem encurta sem
	// senha não pode receber um link que não conseguiria abrir.
	FindByURLHash(ctx context.Context, urlHash string) (URLData, error)
	FindForRedirect(ctx context.Context, shortID string) (URLData, error)
	FindByShortID(ctx context.Context, shortID string) (URLData, error)
	IncrementAccessCount(ctx context.Context, shortID string) error
	CountURLs(ctx context.Context) (int, error)
	InsertClickEvent(ctx context.Context, e ClickEvent) error
	ClickStats(ctx context.Context, shortID string) (ClickStats, error)
	// ManagementHash devolve o hash do token e se o short_id existe. Hash
	// vazio = link não-gerenciável ou inexistente (exists distingue).
	ManagementHash(ctx context.Context, shortID string) (hash string, exists bool, err error)
	// SoftDelete marca o link como deletado (idempotente). Devolve true se
	// alterou uma linha (era ativo); false se já estava deletado.
	SoftDelete(ctx context.Context, shortID string) (bool, error)
}
