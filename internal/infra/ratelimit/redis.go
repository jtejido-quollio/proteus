package ratelimit

import (
	"context"
	"errors"
	"time"

	"proteus/internal/domain"

	"github.com/redis/go-redis/v9"
)

type redisLimiter struct {
	client *redis.Client
	now    func() time.Time
}

var redisAllowScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {current, ttl}
`)

func NewRedisLimiter(addr, password string, db int, now func() time.Time) (domain.RateLimiter, error) {
	if addr == "" {
		return nil, errors.New("redis addr is required")
	}
	if now == nil {
		now = time.Now
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &redisLimiter{client: client, now: now}, nil
}

func (r *redisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitDecision, error) {
	if limit <= 0 {
		return domain.RateLimitDecision{Allowed: true, Limit: limit, Remaining: limit}, nil
	}
	windowMillis := window.Milliseconds()
	if windowMillis <= 0 {
		windowMillis = 1000
	}
	result, err := redisAllowScript.Run(ctx, r.client, []string{key}, windowMillis).Result()
	if err != nil {
		return domain.RateLimitDecision{}, err
	}
	values, ok := result.([]any)
	if !ok || len(values) < 2 {
		return domain.RateLimitDecision{}, errors.New("unexpected redis rate limit response")
	}
	current, ok := values[0].(int64)
	if !ok {
		return domain.RateLimitDecision{}, errors.New("invalid redis counter response")
	}
	ttlMillis, _ := values[1].(int64)
	resetAt := r.now()
	if ttlMillis > 0 {
		resetAt = resetAt.Add(time.Duration(ttlMillis) * time.Millisecond)
	}
	remaining := limit - int(current)
	if remaining < 0 {
		remaining = 0
	}
	allowed := current <= int64(limit)
	return domain.RateLimitDecision{
		Allowed:   allowed,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}
