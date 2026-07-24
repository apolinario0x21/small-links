package http

import (
	"net/http"
	"sync"
	"time"

	"github.com/apolinario0x21/small-links/internal/metrics"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	// 10 criações por minuto por IP, com burst de 10.
	rateLimitPerMinute = 10
	rateLimitBurst     = 10

	// Tentativas de senha, por SHORT_ID (não por IP): a força bruta contra um
	// link é distribuível entre IPs, então o alvo é a chave certa para limitar.
	passwordRatePerMinute = 5
	passwordRateBurst     = 5

	limiterTTL             = 3 * time.Minute
	limiterCleanupInterval = time.Minute
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// keyRateLimiter mantém um rate.Limiter por chave (IP nas criações,
// short_id nas tentativas de senha), com limpeza periódica das entradas
// ociosas.
type keyRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	limit   rate.Limit
	burst   int
}

func newKeyRateLimiter(perMinute, burst int) *keyRateLimiter {
	l := &keyRateLimiter{
		entries: make(map[string]*limiterEntry),
		limit:   rate.Limit(float64(perMinute) / 60.0),
		burst:   burst,
	}

	go l.cleanupLoop()

	return l
}

func (l *keyRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = entry
	}
	entry.lastSeen = time.Now()

	return entry.limiter.Allow()
}

func (l *keyRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(limiterCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		for key, entry := range l.entries {
			if time.Since(entry.lastSeen) > limiterTTL {
				delete(l.entries, key)
			}
		}
		l.mu.Unlock()
	}
}

// byIP limita por IP do cliente — a chave das criações.
func (l *keyRateLimiter) byIP() gin.HandlerFunc {
	return l.middleware(func(c *gin.Context) string { return c.ClientIP() })
}

// byShortID limita por link alvo — a chave das tentativas de senha, que um
// atacante distribuiria entre IPs.
func (l *keyRateLimiter) byShortID() gin.HandlerFunc {
	return l.middleware(func(c *gin.Context) string { return c.Param("shortId") })
}

func (l *keyRateLimiter) middleware(keyOf func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.allow(keyOf(c)) {
			metrics.RateLimitedTotal.Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded, try again later"})
			return
		}
		c.Next()
	}
}
