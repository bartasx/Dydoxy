package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v9"
)

const (
	userLimitsKeyPrefix = "user_limits:"
	orgLimitsKeyPrefix  = "org_limits:"
	usageKeyPrefix      = "usage:"
	limitStatsKey       = "limit_stats"
)

// RedisUserOrgLimitStorage implements UserOrgLimitStorage using Redis
type RedisUserOrgLimitStorage struct {
	client *redis.Client
}

// NewRedisUserOrgLimitStorage creates a new Redis-based user/org limit storage
func NewRedisUserOrgLimitStorage(client *redis.Client) *RedisUserOrgLimitStorage {
	return &RedisUserOrgLimitStorage{
		client: client,
	}
}

// SaveUserLimits saves user limits to Redis
func (s *RedisUserOrgLimitStorage) SaveUserLimits(ctx context.Context, limits *UserLimits) error {
	data, err := json.Marshal(limits)
	if err != nil {
		return fmt.Errorf("failed to marshal user limits: %w", err)
	}
	
	key := userLimitsKeyPrefix + limits.UserID
	
	// Set expiration if specified
	var expiration time.Duration
	if limits.ExpiresAt != nil {
		expiration = time.Until(*limits.ExpiresAt)
		if expiration <= 0 {
			return fmt.Errorf("user limits already expired")
		}
	}
	
	if err := s.client.Set(ctx, key, data, expiration).Err(); err != nil {
		return fmt.Errorf("failed to save user limits to Redis: %w", err)
	}
	
	return nil
}

// LoadUserLimits loads user limits from Redis
func (s *RedisUserOrgLimitStorage) LoadUserLimits(ctx context.Context, userID string) (*UserLimits, error) {
	key := userLimitsKeyPrefix + userID
	
	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("user limits not found: %s", userID)
		}
		return nil, fmt.Errorf("failed to load user limits: %w", err)
	}
	
	var limits UserLimits
	if err := json.Unmarshal([]byte(data), &limits); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user limits: %w", err)
	}
	
	return &limits, nil
}

// DeleteUserLimits deletes user limits from Redis
func (s *RedisUserOrgLimitStorage) DeleteUserLimits(ctx context.Context, userID string) error {
	key := userLimitsKeyPrefix + userID
	
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete user limits: %w", err)
	}
	
	return nil
}

// ListUserLimits lists all user limits for an organization
func (s *RedisUserOrgLimitStorage) ListUserLimits(ctx context.Context, orgID string) ([]*UserLimits, error) {
	pattern := userLimitsKeyPrefix + "*"
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user limit keys: %w", err)
	}
	
	var limits []*UserLimits
	
	for _, key := range keys {
		data, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip keys that can't be read
		}
		
		var userLimits UserLimits
		if err := json.Unmarshal([]byte(data), &userLimits); err != nil {
			continue // Skip invalid data
		}
		
		// Filter by organization if specified
		if orgID == "" || userLimits.OrgID == orgID {
			limits = append(limits, &userLimits)
		}
	}
	
	return limits, nil
}

// SaveOrgLimits saves organization limits to Redis
func (s *RedisUserOrgLimitStorage) SaveOrgLimits(ctx context.Context, limits *OrgLimits) error {
	data, err := json.Marshal(limits)
	if err != nil {
		return fmt.Errorf("failed to marshal org limits: %w", err)
	}
	
	key := orgLimitsKeyPrefix + limits.OrgID
	
	if err := s.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save org limits to Redis: %w", err)
	}
	
	return nil
}

// LoadOrgLimits loads organization limits from Redis
func (s *RedisUserOrgLimitStorage) LoadOrgLimits(ctx context.Context, orgID string) (*OrgLimits, error) {
	key := orgLimitsKeyPrefix + orgID
	
	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("org limits not found: %s", orgID)
		}
		return nil, fmt.Errorf("failed to load org limits: %w", err)
	}
	
	var limits OrgLimits
	if err := json.Unmarshal([]byte(data), &limits); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org limits: %w", err)
	}
	
	return &limits, nil
}

// DeleteOrgLimits deletes organization limits from Redis
func (s *RedisUserOrgLimitStorage) DeleteOrgLimits(ctx context.Context, orgID string) error {
	key := orgLimitsKeyPrefix + orgID
	
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete org limits: %w", err)
	}
	
	return nil
}

// ListOrgLimits lists all organization limits
func (s *RedisUserOrgLimitStorage) ListOrgLimits(ctx context.Context) ([]*OrgLimits, error) {
	pattern := orgLimitsKeyPrefix + "*"
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get org limit keys: %w", err)
	}
	
	var limits []*OrgLimits
	
	for _, key := range keys {
		data, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip keys that can't be read
		}
		
		var orgLimits OrgLimits
		if err := json.Unmarshal([]byte(data), &orgLimits); err != nil {
			continue // Skip invalid data
		}
		
		limits = append(limits, &orgLimits)
	}
	
	return limits, nil
}

// IncrementUsage increments usage counter for user/org
func (s *RedisUserOrgLimitStorage) IncrementUsage(ctx context.Context, userID, orgID string, limitType LimitType, amount int64) error {
	now := time.Now()
	
	// Create usage keys for different periods
	keys := s.getUsageKeys(userID, orgID, limitType, now)
	
	pipe := s.client.Pipeline()
	
	for period, key := range keys {
		pipe.IncrBy(ctx, key, amount)
		
		// Set expiration based on period
		var expiration time.Duration
		switch period {
		case "hour":
			expiration = time.Hour
		case "day":
			expiration = 24 * time.Hour
		case "month":
			expiration = 31 * 24 * time.Hour
		}
		
		if expiration > 0 {
			pipe.Expire(ctx, key, expiration)
		}
	}
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment usage: %w", err)
	}
	
	return nil
}

// GetUsage gets usage for user/org in a specific period
func (s *RedisUserOrgLimitStorage) GetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) (int64, error) {
	now := time.Now()
	key := s.getUsageKey(userID, orgID, limitType, period, now)
	
	usage, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil // No usage recorded yet
		}
		return 0, fmt.Errorf("failed to get usage: %w", err)
	}
	
	usageInt, err := strconv.ParseInt(usage, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse usage: %w", err)
	}
	
	return usageInt, nil
}

// ResetUsage resets usage counter for user/org
func (s *RedisUserOrgLimitStorage) ResetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) error {
	now := time.Now()
	key := s.getUsageKey(userID, orgID, limitType, period, now)
	
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to reset usage: %w", err)
	}
	
	return nil
}

// GetLimitStats returns statistics about limits
func (s *RedisUserOrgLimitStorage) GetLimitStats(ctx context.Context) (*LimitStats, error) {
	stats := &LimitStats{
		UsersByTier:  make(map[string]int64),
		OrgsByPlan:   make(map[string]int64),
		LastUpdated:  time.Now(),
	}
	
	// Count users by tier
	userKeys, err := s.client.Keys(ctx, userLimitsKeyPrefix+"*").Result()
	if err == nil {
		stats.TotalUsers = int64(len(userKeys))
		
		for _, key := range userKeys {
			data, err := s.client.Get(ctx, key).Result()
			if err != nil {
				continue
			}
			
			var limits UserLimits
			if err := json.Unmarshal([]byte(data), &limits); err != nil {
				continue
			}
			
			stats.UsersByTier[limits.Tier]++
		}
	}
	
	// Count orgs by plan
	orgKeys, err := s.client.Keys(ctx, orgLimitsKeyPrefix+"*").Result()
	if err == nil {
		stats.TotalOrgs = int64(len(orgKeys))
		
		for _, key := range orgKeys {
			data, err := s.client.Get(ctx, key).Result()
			if err != nil {
				continue
			}
			
			var limits OrgLimits
			if err := json.Unmarshal([]byte(data), &limits); err != nil {
				continue
			}
			
			stats.OrgsByPlan[limits.Plan]++
		}
	}
	
	// Get top usage users and orgs (simplified implementation)
	stats.TopUsageUsers = s.getTopUsageUsers(ctx)
	stats.TopUsageOrgs = s.getTopUsageOrgs(ctx)
	
	return stats, nil
}

// getUsageKeys generates usage keys for different periods
func (s *RedisUserOrgLimitStorage) getUsageKeys(userID, orgID string, limitType LimitType, now time.Time) map[string]string {
	keys := make(map[string]string)
	
	// Hour key
	hourKey := s.getUsageKey(userID, orgID, limitType, PeriodHour, now)
	keys["hour"] = hourKey
	
	// Day key
	dayKey := s.getUsageKey(userID, orgID, limitType, PeriodDay, now)
	keys["day"] = dayKey
	
	// Month key
	monthKey := s.getUsageKey(userID, orgID, limitType, PeriodMonth, now)
	keys["month"] = monthKey
	
	return keys
}

// getUsageKey generates a usage key for a specific period
func (s *RedisUserOrgLimitStorage) getUsageKey(userID, orgID string, limitType LimitType, period LimitPeriod, now time.Time) string {
	var timeKey string
	
	switch period {
	case PeriodHour:
		timeKey = now.Format("2006010215") // YYYYMMDDHH
	case PeriodDay:
		timeKey = now.Format("20060102") // YYYYMMDD
	case PeriodMonth:
		timeKey = now.Format("200601") // YYYYMM
	}
	
	// If userID is empty, this is org-level usage
	if userID == "" {
		return fmt.Sprintf("%sorg:%s:%s:%s:%s", usageKeyPrefix, orgID, limitType, period, timeKey)
	}
	
	return fmt.Sprintf("%suser:%s:%s:%s:%s:%s", usageKeyPrefix, userID, orgID, limitType, period, timeKey)
}

// getTopUsageUsers returns top usage users (simplified implementation)
func (s *RedisUserOrgLimitStorage) getTopUsageUsers(ctx context.Context) []UserUsage {
	// This is a simplified implementation
	// In a real system, you'd want to maintain sorted sets for efficient top-K queries
	return []UserUsage{}
}

// getTopUsageOrgs returns top usage organizations (simplified implementation)
func (s *RedisUserOrgLimitStorage) getTopUsageOrgs(ctx context.Context) []OrgUsage {
	// This is a simplified implementation
	// In a real system, you'd want to maintain sorted sets for efficient top-K queries
	return []OrgUsage{}
}

// GetUsagePattern returns usage pattern for analysis
func (s *RedisUserOrgLimitStorage) GetUsagePattern(ctx context.Context, userID, orgID string, limitType LimitType, days int) (map[string]int64, error) {
	pattern := make(map[string]int64)
	now := time.Now()
	
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -i)
		key := s.getUsageKey(userID, orgID, limitType, PeriodDay, date)
		
		usage, err := s.client.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				pattern[date.Format("2006-01-02")] = 0
			}
			continue
		}
		
		usageInt, err := strconv.ParseInt(usage, 10, 64)
		if err != nil {
			continue
		}
		
		pattern[date.Format("2006-01-02")] = usageInt
	}
	
	return pattern, nil
}

// CleanupExpiredUsage removes old usage data
func (s *RedisUserOrgLimitStorage) CleanupExpiredUsage(ctx context.Context) (int64, error) {
	// Get all usage keys
	keys, err := s.client.Keys(ctx, usageKeyPrefix+"*").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get usage keys: %w", err)
	}
	
	var expiredKeys []string
	now := time.Now()
	
	for _, key := range keys {
		// Parse the time from the key
		parts := strings.Split(key, ":")
		if len(parts) < 6 {
			continue
		}
		
		timeKey := parts[len(parts)-1]
		period := parts[len(parts)-2]
		
		var keyTime time.Time
		var maxAge time.Duration
		
		switch period {
		case "hour":
			keyTime, err = time.Parse("2006010215", timeKey)
			maxAge = 24 * time.Hour // Keep hourly data for 1 day
		case "day":
			keyTime, err = time.Parse("20060102", timeKey)
			maxAge = 90 * 24 * time.Hour // Keep daily data for 90 days
		case "month":
			keyTime, err = time.Parse("200601", timeKey)
			maxAge = 365 * 24 * time.Hour // Keep monthly data for 1 year
		default:
			continue
		}
		
		if err != nil {
			continue
		}
		
		if now.Sub(keyTime) > maxAge {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	// Delete expired keys
	if len(expiredKeys) > 0 {
		deleted, err := s.client.Del(ctx, expiredKeys...).Result()
		if err != nil {
			return 0, fmt.Errorf("failed to delete expired usage keys: %w", err)
		}
		return deleted, nil
	}
	
	return 0, nil
}