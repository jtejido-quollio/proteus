package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"

	"proteus/internal/domain"
)

type memoryLimiter struct {
	mu   sync.Mutex
	now  func() time.Time
	data map[string]*memoryBucket
	maxKeys int
}

type memoryBucket struct {
	count    int
	windowEnd time.Time
}

type MemoryLimiterConfig struct {
	Now     func() time.Time
	MaxKeys int
}

func NewMemoryLimiter(cfg MemoryLimiterConfig) domain.RateLimiter {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 10000
	}
	return &memoryLimiter{
		now:     cfg.Now,
		data:    make(map[string]*memoryBucket),
		maxKeys: cfg.MaxKeys,
	}
}

func (m *memoryLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (domain.RateLimitDecision, error) {
	if limit <= 0 {
		return domain.RateLimitDecision{Allowed: true, Limit: limit, Remaining: limit}, nil
	}
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	bucket, ok := m.data[key]
	if ok && now.After(bucket.windowEnd) {
		delete(m.data, key)
		bucket = nil
		ok = false
	}
	if !ok || now.After(bucket.windowEnd) {
		if len(m.data) >= m.maxKeys {
			m.gc(now)
		}
		if len(m.data) >= m.maxKeys {
			return domain.RateLimitDecision{}, errors.New("rate limiter capacity exceeded")
		}
		bucket = &memoryBucket{
			count:    0,
			windowEnd: now.Add(window),
		}
		m.data[key] = bucket
	}

	if bucket.count < limit {
		bucket.count++
		remaining := limit - bucket.count
		return domain.RateLimitDecision{
			Allowed:   true,
			Limit:     limit,
			Remaining: remaining,
			ResetAt:   bucket.windowEnd,
		}, nil
	}

	return domain.RateLimitDecision{
		Allowed:   false,
		Limit:     limit,
		Remaining: 0,
		ResetAt:   bucket.windowEnd,
	}, nil
}

func (m *memoryLimiter) gc(now time.Time) {
	for key, bucket := range m.data {
		if now.After(bucket.windowEnd) {
			delete(m.data, key)
		}
	}
}
