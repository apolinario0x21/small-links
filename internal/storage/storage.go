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
	CreatedAt   time.Time
	AccessCount int
}

type Repository interface {
	Insert(ctx context.Context, data URLData) error
	FindForRedirect(ctx context.Context, shortID string) (URLData, error)
	FindByShortID(ctx context.Context, shortID string) (URLData, error)
	IncrementAccessCount(ctx context.Context, shortID string) error
	CountURLs(ctx context.Context) (int, error)
}
