package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
	"golang.org/x/time/rate"
)

// Legacy Limiter for backward compatibility
type Limiter struct {
	redis  *redis.Client
	limits map[string]*rate.Limiter
}

// Legacy Config for backward compatibility
type Config struct {
	RequestsPerMinute int
	BurstSize         int
}

// NewLimiter creates a legacy limiter (deprecated, use TokenBucketManager instead)
func NewLimiter(redisClient *redis.Client) *Limiter {
	return &Limiter{
		redis:  redisClient,
		limits: make(map[string]*rate.Limiter),
	}
}

// Allow checks if a request should be allowed (legacy method)
func (l *Limiter) Allow(userID string, config Config) bool {
	key := fmt.Sprintf("legacy_rate_limit:%s", userID)
	
	// Check Redis for distributed rate limiting
	ctx := context.Background()
	current, err := l.redis.Incr(ctx, key).Result()
	if err != nil {
		return false
	}
	
	if current == 1 {
		l.redis.Expire(ctx, key, time.Minute)
	}
	
	return current <= int64(config.RequestsPerMinute)
}

// GetLimiter returns a rate limiter for a user (legacy method)
func (l *Limiter) GetLimiter(userID string, config Config) *rate.Limiter {
	if limiter, exists := l.limits[userID]; exists {
		return limiter
	}
	
	limiter := rate.NewLimiter(rate.Every(time.Minute/time.Duration(config.RequestsPerMinute)), config.BurstSize)
	l.limits[userID] = limiter
	return limiter
}

// ConvertToTokenBucketConfig converts legacy config to token bucket config
func (c *Config) ConvertToTokenBucketConfig() *BucketConfig {
	return &BucketConfig{
		Capacity:   int64(c.BurstSize),
		RefillRate: int64(c.RequestsPerMinute) / 60, // Convert per minute to per second
	}
}