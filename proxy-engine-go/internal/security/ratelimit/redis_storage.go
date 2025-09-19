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
	bucketKeyPrefix = "rate_limit:buckets:"
	configKeyPrefix = "rate_limit:configs:"
	statsKey        = "rate_limit:stats"
	bucketListKey   = "rate_limit:bucket_list"
)

// RedisBucketStorage implements BucketStorage using Redis
type RedisBucketStorage struct {
	client *redis.Client
}

// BucketData represents serialized bucket data
type BucketData struct {
	Capacity   int64     `json:"capacity"`
	Tokens     int64     `json:"tokens"`
	RefillRate int64     `json:"refill_rate"`
	LastRefill time.Time `json:"last_refill"`
}

// NewRedisBucketStorage creates a new Redis-based bucket storage
func NewRedisBucketStorage(client *redis.Client) *RedisBucketStorage {
	return &RedisBucketStorage{
		client: client,
	}
}

// SaveBucket saves bucket state to Redis
func (s *RedisBucketStorage) SaveBucket(ctx context.Context, key string, bucket *TokenBucket) error {
	data := &BucketData{
		Capacity:   bucket.capacity,
		Tokens:     bucket.tokens,
		RefillRate: bucket.refillRate,
		LastRefill: bucket.lastRefill,
	}
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal bucket data: %w", err)
	}
	
	bucketKey := bucketKeyPrefix + key
	
	pipe := s.client.Pipeline()
	
	// Save bucket data with TTL
	pipe.Set(ctx, bucketKey, jsonData, 30*time.Minute)
	
	// Add to bucket list for tracking
	pipe.SAdd(ctx, bucketListKey, key)
	
	// Update stats
	pipe.HIncrBy(ctx, statsKey, "total_requests", 1)
	
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to save bucket to Redis: %w", err)
	}
	
	return nil
}

// LoadBucket loads bucket state from Redis
func (s *RedisBucketStorage) LoadBucket(ctx context.Context, key string) (*TokenBucket, error) {
	bucketKey := bucketKeyPrefix + key
	
	jsonData, err := s.client.Get(ctx, bucketKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("bucket not found: %s", key)
		}
		return nil, fmt.Errorf("failed to load bucket: %w", err)
	}
	
	var data BucketData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bucket data: %w", err)
	}
	
	bucket := &TokenBucket{
		capacity:   data.Capacity,
		tokens:     data.Tokens,
		refillRate: data.RefillRate,
		lastRefill: data.LastRefill,
	}
	
	return bucket, nil
}

// DeleteBucket removes bucket from Redis
func (s *RedisBucketStorage) DeleteBucket(ctx context.Context, key string) error {
	bucketKey := bucketKeyPrefix + key
	
	pipe := s.client.Pipeline()
	
	// Delete bucket data
	pipe.Del(ctx, bucketKey)
	
	// Remove from bucket list
	pipe.SRem(ctx, bucketListKey, key)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete bucket from Redis: %w", err)
	}
	
	return nil
}

// SaveConfig saves bucket configuration to Redis
func (s *RedisBucketStorage) SaveConfig(ctx context.Context, name string, config *BucketConfig) error {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	configKey := configKeyPrefix + name
	
	if err := s.client.Set(ctx, configKey, jsonData, 0).Err(); err != nil {
		return fmt.Errorf("failed to save config to Redis: %w", err)
	}
	
	return nil
}

// LoadConfig loads bucket configuration from Redis
func (s *RedisBucketStorage) LoadConfig(ctx context.Context, name string) (*BucketConfig, error) {
	configKey := configKeyPrefix + name
	
	jsonData, err := s.client.Get(ctx, configKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("config not found: %s", name)
		}
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	
	var config BucketConfig
	if err := json.Unmarshal([]byte(jsonData), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	return &config, nil
}

// ListBuckets returns all bucket keys
func (s *RedisBucketStorage) ListBuckets(ctx context.Context) ([]string, error) {
	buckets, err := s.client.SMembers(ctx, bucketListKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}
	
	return buckets, nil
}

// GetStats returns storage statistics
func (s *RedisBucketStorage) GetStats(ctx context.Context) (*BucketStats, error) {
	stats := &BucketStats{
		ConfigsByType: make(map[string]int64),
		LastUpdated:   time.Now(),
	}
	
	// Get basic stats from hash
	statsData, err := s.client.HGetAll(ctx, statsKey).Result()
	if err == nil {
		if val, exists := statsData["total_requests"]; exists {
			if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
				stats.TotalRequests = parsed
			}
		}
		if val, exists := statsData["allowed_requests"]; exists {
			if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
				stats.AllowedRequests = parsed
			}
		}
		if val, exists := statsData["denied_requests"]; exists {
			if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
				stats.DeniedRequests = parsed
			}
		}
	}
	
	// Count total buckets
	totalBuckets, err := s.client.SCard(ctx, bucketListKey).Result()
	if err == nil {
		stats.TotalBuckets = totalBuckets
	}
	
	// Count active buckets (those that exist in Redis)
	bucketKeys, err := s.client.Keys(ctx, bucketKeyPrefix+"*").Result()
	if err == nil {
		stats.ActiveBuckets = int64(len(bucketKeys))
	}
	
	// Count configs by type
	configKeys, err := s.client.Keys(ctx, configKeyPrefix+"*").Result()
	if err == nil {
		for _, key := range configKeys {
			configName := strings.TrimPrefix(key, configKeyPrefix)
			stats.ConfigsByType[configName] = 1
		}
	}
	
	return stats, nil
}

// IncrementAllowed increments allowed requests counter
func (s *RedisBucketStorage) IncrementAllowed(ctx context.Context) error {
	return s.client.HIncrBy(ctx, statsKey, "allowed_requests", 1).Err()
}

// IncrementDenied increments denied requests counter
func (s *RedisBucketStorage) IncrementDenied(ctx context.Context) error {
	return s.client.HIncrBy(ctx, statsKey, "denied_requests", 1).Err()
}

// CleanupExpiredBuckets removes expired buckets from tracking
func (s *RedisBucketStorage) CleanupExpiredBuckets(ctx context.Context) (int64, error) {
	// Get all tracked buckets
	buckets, err := s.client.SMembers(ctx, bucketListKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get bucket list: %w", err)
	}
	
	var expiredBuckets []string
	
	// Check which buckets no longer exist in Redis
	for _, bucket := range buckets {
		bucketKey := bucketKeyPrefix + bucket
		exists, err := s.client.Exists(ctx, bucketKey).Result()
		if err != nil {
			continue
		}
		
		if exists == 0 {
			expiredBuckets = append(expiredBuckets, bucket)
		}
	}
	
	// Remove expired buckets from tracking list
	if len(expiredBuckets) > 0 {
		pipe := s.client.Pipeline()
		for _, bucket := range expiredBuckets {
			pipe.SRem(ctx, bucketListKey, bucket)
		}
		_, err := pipe.Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to cleanup expired buckets: %w", err)
		}
	}
	
	return int64(len(expiredBuckets)), nil
}

// GetBucketKeys returns all bucket keys with optional pattern matching
func (s *RedisBucketStorage) GetBucketKeys(ctx context.Context, pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*"
	}
	
	searchPattern := bucketKeyPrefix + pattern
	keys, err := s.client.Keys(ctx, searchPattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket keys: %w", err)
	}
	
	// Remove prefix from keys
	var bucketKeys []string
	for _, key := range keys {
		bucketKey := strings.TrimPrefix(key, bucketKeyPrefix)
		bucketKeys = append(bucketKeys, bucketKey)
	}
	
	return bucketKeys, nil
}

// GetConfigNames returns all configuration names
func (s *RedisBucketStorage) GetConfigNames(ctx context.Context) ([]string, error) {
	keys, err := s.client.Keys(ctx, configKeyPrefix+"*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get config keys: %w", err)
	}
	
	// Remove prefix from keys
	var configNames []string
	for _, key := range keys {
		configName := strings.TrimPrefix(key, configKeyPrefix)
		configNames = append(configNames, configName)
	}
	
	return configNames, nil
}

// ResetStats resets all statistics
func (s *RedisBucketStorage) ResetStats(ctx context.Context) error {
	return s.client.Del(ctx, statsKey).Err()
}