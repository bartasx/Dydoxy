package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	capacity     int64         // Maximum number of tokens
	tokens       int64         // Current number of tokens
	refillRate   int64         // Tokens added per second
	lastRefill   time.Time     // Last refill timestamp
	mu           sync.Mutex    // Mutex for thread safety
}

// BucketConfig represents configuration for a token bucket
type BucketConfig struct {
	Capacity   int64         `json:"capacity"`   // Maximum tokens
	RefillRate int64         `json:"refill_rate"` // Tokens per second
	InitialTokens int64      `json:"initial_tokens,omitempty"` // Initial token count
}

// TokenBucketManager manages multiple token buckets
type TokenBucketManager struct {
	buckets    map[string]*TokenBucket
	configs    map[string]*BucketConfig
	storage    BucketStorage
	logger     *logrus.Logger
	mu         sync.RWMutex
	cleanupInterval time.Duration
	bucketTTL      time.Duration
	stopCleanup    chan struct{}
}

// BucketStorage defines interface for persistent bucket storage
type BucketStorage interface {
	// SaveBucket saves bucket state to storage
	SaveBucket(ctx context.Context, key string, bucket *TokenBucket) error
	
	// LoadBucket loads bucket state from storage
	LoadBucket(ctx context.Context, key string) (*TokenBucket, error)
	
	// DeleteBucket removes bucket from storage
	DeleteBucket(ctx context.Context, key string) error
	
	// SaveConfig saves bucket configuration
	SaveConfig(ctx context.Context, key string, config *BucketConfig) error
	
	// LoadConfig loads bucket configuration
	LoadConfig(ctx context.Context, key string) (*BucketConfig, error)
	
	// ListBuckets returns all bucket keys
	ListBuckets(ctx context.Context) ([]string, error)
	
	// GetStats returns storage statistics
	GetStats(ctx context.Context) (*BucketStats, error)
}

// BucketStats represents statistics for token buckets
type BucketStats struct {
	TotalBuckets    int64            `json:"total_buckets"`
	ActiveBuckets   int64            `json:"active_buckets"`
	TotalRequests   int64            `json:"total_requests"`
	AllowedRequests int64            `json:"allowed_requests"`
	DeniedRequests  int64            `json:"denied_requests"`
	ConfigsByType   map[string]int64 `json:"configs_by_type"`
	LastUpdated     time.Time        `json:"last_updated"`
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool      `json:"allowed"`
	TokensLeft    int64     `json:"tokens_left"`
	RetryAfter    int64     `json:"retry_after_seconds,omitempty"`
	ResetTime     time.Time `json:"reset_time"`
	BucketKey     string    `json:"bucket_key"`
	ConfigUsed    string    `json:"config_used"`
	Timestamp     time.Time `json:"timestamp"`
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(config *BucketConfig) *TokenBucket {
	initialTokens := config.Capacity
	if config.InitialTokens > 0 {
		initialTokens = config.InitialTokens
	}
	
	return &TokenBucket{
		capacity:   config.Capacity,
		tokens:     initialTokens,
		refillRate: config.RefillRate,
		lastRefill: time.Now(),
	}
}

// TryConsume attempts to consume tokens from the bucket
func (tb *TokenBucket) TryConsume(tokens int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	
	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}
	
	return false
}

// GetTokens returns the current number of tokens
func (tb *TokenBucket) GetTokens() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	return tb.tokens
}

// GetCapacity returns the bucket capacity
func (tb *TokenBucket) GetCapacity() int64 {
	return tb.capacity
}

// GetRefillRate returns the refill rate
func (tb *TokenBucket) GetRefillRate() int64 {
	return tb.refillRate
}

// TimeToRefill returns the time needed to refill to capacity
func (tb *TokenBucket) TimeToRefill() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	
	if tb.tokens >= tb.capacity {
		return 0
	}
	
	tokensNeeded := tb.capacity - tb.tokens
	secondsNeeded := float64(tokensNeeded) / float64(tb.refillRate)
	
	return time.Duration(secondsNeeded * float64(time.Second))
}

// TimeToTokens returns the time needed to have specified tokens
func (tb *TokenBucket) TimeToTokens(tokens int64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	
	if tb.tokens >= tokens {
		return 0
	}
	
	tokensNeeded := tokens - tb.tokens
	secondsNeeded := float64(tokensNeeded) / float64(tb.refillRate)
	
	return time.Duration(secondsNeeded * float64(time.Second))
}

// Reset resets the bucket to full capacity
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.tokens = tb.capacity
	tb.lastRefill = time.Now()
}

// UpdateConfig updates the bucket configuration
func (tb *TokenBucket) UpdateConfig(config *BucketConfig) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	// Refill with old rate first
	tb.refill()
	
	// Update configuration
	oldCapacity := tb.capacity
	tb.capacity = config.Capacity
	tb.refillRate = config.RefillRate
	
	// Adjust tokens if capacity changed
	if tb.capacity < oldCapacity && tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

// refill adds tokens based on elapsed time (must be called with lock held)
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	
	if elapsed <= 0 {
		return
	}
	
	tokensToAdd := int64(elapsed.Seconds()) * tb.refillRate
	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// NewTokenBucketManager creates a new token bucket manager
func NewTokenBucketManager(storage BucketStorage, logger *logrus.Logger) *TokenBucketManager {
	manager := &TokenBucketManager{
		buckets:         make(map[string]*TokenBucket),
		configs:         make(map[string]*BucketConfig),
		storage:         storage,
		logger:          logger,
		cleanupInterval: 5 * time.Minute,
		bucketTTL:       30 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}
	
	// Start cleanup goroutine
	go manager.cleanupLoop()
	
	return manager
}

// CheckRateLimit checks if a request should be allowed
func (tbm *TokenBucketManager) CheckRateLimit(ctx context.Context, key string, tokens int64, configName string) (*RateLimitResult, error) {
	bucket, config, err := tbm.getBucket(ctx, key, configName)
	if err != nil {
		return nil, err
	}
	
	allowed := bucket.TryConsume(tokens)
	tokensLeft := bucket.GetTokens()
	
	result := &RateLimitResult{
		Allowed:    allowed,
		TokensLeft: tokensLeft,
		BucketKey:  key,
		ConfigUsed: configName,
		Timestamp:  time.Now(),
	}
	
	if !allowed {
		result.RetryAfter = int64(bucket.TimeToTokens(tokens).Seconds())
		result.ResetTime = time.Now().Add(bucket.TimeToRefill())
	}
	
	// Save bucket state to storage
	if err := tbm.storage.SaveBucket(ctx, key, bucket); err != nil {
		tbm.logger.Warnf("Failed to save bucket state: %v", err)
	}
	
	return result, nil
}

// SetConfig sets a rate limit configuration
func (tbm *TokenBucketManager) SetConfig(ctx context.Context, name string, config *BucketConfig) error {
	if err := tbm.validateConfig(config); err != nil {
		return err
	}
	
	tbm.mu.Lock()
	tbm.configs[name] = config
	tbm.mu.Unlock()
	
	// Save config to storage
	if err := tbm.storage.SaveConfig(ctx, name, config); err != nil {
		return err
	}
	
	tbm.logger.Infof("Set rate limit config '%s': capacity=%d, refill_rate=%d", 
		name, config.Capacity, config.RefillRate)
	
	return nil
}

// GetConfig gets a rate limit configuration
func (tbm *TokenBucketManager) GetConfig(ctx context.Context, name string) (*BucketConfig, error) {
	tbm.mu.RLock()
	config, exists := tbm.configs[name]
	tbm.mu.RUnlock()
	
	if exists {
		return config, nil
	}
	
	// Try to load from storage
	config, err := tbm.storage.LoadConfig(ctx, name)
	if err != nil {
		return nil, err
	}
	
	tbm.mu.Lock()
	tbm.configs[name] = config
	tbm.mu.Unlock()
	
	return config, nil
}

// ResetBucket resets a specific bucket
func (tbm *TokenBucketManager) ResetBucket(ctx context.Context, key string) error {
	tbm.mu.Lock()
	bucket, exists := tbm.buckets[key]
	tbm.mu.Unlock()
	
	if !exists {
		return nil // Bucket doesn't exist, nothing to reset
	}
	
	bucket.Reset()
	
	// Save reset state to storage
	if err := tbm.storage.SaveBucket(ctx, key, bucket); err != nil {
		return err
	}
	
	tbm.logger.Infof("Reset bucket: %s", key)
	return nil
}

// GetBucketInfo returns information about a bucket
func (tbm *TokenBucketManager) GetBucketInfo(ctx context.Context, key string) (*RateLimitResult, error) {
	tbm.mu.RLock()
	bucket, exists := tbm.buckets[key]
	tbm.mu.RUnlock()
	
	if !exists {
		return nil, nil // Bucket doesn't exist
	}
	
	tokensLeft := bucket.GetTokens()
	
	return &RateLimitResult{
		Allowed:    tokensLeft > 0,
		TokensLeft: tokensLeft,
		ResetTime:  time.Now().Add(bucket.TimeToRefill()),
		BucketKey:  key,
		Timestamp:  time.Now(),
	}, nil
}

// GetStats returns statistics about all buckets
func (tbm *TokenBucketManager) GetStats(ctx context.Context) (*BucketStats, error) {
	return tbm.storage.GetStats(ctx)
}

// Close stops the manager and cleanup goroutine
func (tbm *TokenBucketManager) Close() {
	close(tbm.stopCleanup)
}

// getBucket gets or creates a bucket for the given key
func (tbm *TokenBucketManager) getBucket(ctx context.Context, key, configName string) (*TokenBucket, *BucketConfig, error) {
	tbm.mu.RLock()
	bucket, exists := tbm.buckets[key]
	tbm.mu.RUnlock()
	
	if exists {
		tbm.mu.RLock()
		config := tbm.configs[configName]
		tbm.mu.RUnlock()
		return bucket, config, nil
	}
	
	// Get configuration
	config, err := tbm.GetConfig(ctx, configName)
	if err != nil {
		return nil, nil, err
	}
	
	// Try to load bucket from storage
	bucket, err = tbm.storage.LoadBucket(ctx, key)
	if err != nil {
		// Create new bucket if not found in storage
		bucket = NewTokenBucket(config)
	}
	
	tbm.mu.Lock()
	tbm.buckets[key] = bucket
	tbm.mu.Unlock()
	
	return bucket, config, nil
}

// validateConfig validates a bucket configuration
func (tbm *TokenBucketManager) validateConfig(config *BucketConfig) error {
	if config.Capacity <= 0 {
		return fmt.Errorf("capacity must be positive")
	}
	
	if config.RefillRate <= 0 {
		return fmt.Errorf("refill rate must be positive")
	}
	
	if config.InitialTokens < 0 {
		return fmt.Errorf("initial tokens cannot be negative")
	}
	
	if config.InitialTokens > config.Capacity {
		return fmt.Errorf("initial tokens cannot exceed capacity")
	}
	
	return nil
}

// cleanupLoop periodically removes unused buckets
func (tbm *TokenBucketManager) cleanupLoop() {
	ticker := time.NewTicker(tbm.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tbm.cleanup()
		case <-tbm.stopCleanup:
			return
		}
	}
}

// cleanup removes unused buckets from memory
func (tbm *TokenBucketManager) cleanup() {
	tbm.mu.Lock()
	defer tbm.mu.Unlock()
	
	cutoff := time.Now().Add(-tbm.bucketTTL)
	var toDelete []string
	
	for key, bucket := range tbm.buckets {
		// Remove buckets that haven't been used recently
		if bucket.lastRefill.Before(cutoff) {
			toDelete = append(toDelete, key)
		}
	}
	
	for _, key := range toDelete {
		delete(tbm.buckets, key)
	}
	
	if len(toDelete) > 0 {
		tbm.logger.Infof("Cleaned up %d unused buckets", len(toDelete))
	}
}