package domain

import (
	"context"
	"time"
)

type RateLimitDecision struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetAt   time.Time
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (RateLimitDecision, error)
}
