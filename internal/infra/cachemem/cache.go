package cachemem

import (
	"context"
	"sync"
	"time"

	"proteus/internal/domain"
	"proteus/internal/usecase"
)

type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	value     domain.VerificationResult
	expiresAt time.Time
	hasExpiry bool
}

func New() *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
	}
}

func (c *Cache) Get(ctx context.Context, key string) (*domain.VerificationResult, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	if entry.hasExpiry && time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false, nil
	}
	value := entry.value
	return &value, true, nil
}

func (c *Cache) Put(ctx context.Context, key string, value domain.VerificationResult, ttl time.Duration) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := cacheEntry{value: value}
	if ttl > 0 {
		entry.hasExpiry = true
		entry.expiresAt = time.Now().Add(ttl)
	}
	c.entries[key] = entry
	return nil
}

var _ usecase.VerificationCache = (*Cache)(nil)
