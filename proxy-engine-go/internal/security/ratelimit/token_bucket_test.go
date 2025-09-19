package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBucketStorage is a mock implementation of BucketStorage
type MockBucketStorage struct {
	mock.Mock
}

func (m *MockBucketStorage) SaveBucket(ctx context.Context, key string, bucket *TokenBucket) error {
	args := m.Called(ctx, key, bucket)
	return args.Error(0)
}

func (m *MockBucketStorage) LoadBucket(ctx context.Context, key string) (*TokenBucket, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenBucket), args.Error(1)
}

func (m *MockBucketStorage) DeleteBucket(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockBucketStorage) SaveConfig(ctx context.Context, key string, config *BucketConfig) error {
	args := m.Called(ctx, key, config)
	return args.Error(0)
}

func (m *MockBucketStorage) LoadConfig(ctx context.Context, key string) (*BucketConfig, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*BucketConfig), args.Error(1)
}

func (m *MockBucketStorage) ListBuckets(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockBucketStorage) GetStats(ctx context.Context) (*BucketStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*BucketStats), args.Error(1)
}

func TestTokenBucket_TryConsume(t *testing.T) {
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 1, // 1 token per second
	}
	
	bucket := NewTokenBucket(config)
	
	// Should be able to consume tokens up to capacity
	for i := 0; i < 10; i++ {
		assert.True(t, bucket.TryConsume(1), "Should be able to consume token %d", i+1)
	}
	
	// Should not be able to consume more tokens
	assert.False(t, bucket.TryConsume(1), "Should not be able to consume when bucket is empty")
	
	// Wait for refill and try again
	time.Sleep(1100 * time.Millisecond) // Wait slightly more than 1 second
	assert.True(t, bucket.TryConsume(1), "Should be able to consume after refill")
}

func TestTokenBucket_Refill(t *testing.T) {
	config := &BucketConfig{
		Capacity:   5,
		RefillRate: 2, // 2 tokens per second
	}
	
	bucket := NewTokenBucket(config)
	
	// Consume all tokens
	for i := 0; i < 5; i++ {
		assert.True(t, bucket.TryConsume(1))
	}
	
	// Wait for partial refill
	time.Sleep(1100 * time.Millisecond) // Should add 2 tokens
	
	// Should be able to consume 2 tokens
	assert.True(t, bucket.TryConsume(1))
	assert.True(t, bucket.TryConsume(1))
	assert.False(t, bucket.TryConsume(1))
}

func TestTokenBucket_GetTokens(t *testing.T) {
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 1,
	}
	
	bucket := NewTokenBucket(config)
	
	// Initial tokens should equal capacity
	assert.Equal(t, int64(10), bucket.GetTokens())
	
	// Consume some tokens
	bucket.TryConsume(3)
	assert.Equal(t, int64(7), bucket.GetTokens())
}

func TestTokenBucket_TimeToRefill(t *testing.T) {
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 2, // 2 tokens per second
	}
	
	bucket := NewTokenBucket(config)
	
	// Full bucket should have 0 time to refill
	assert.Equal(t, time.Duration(0), bucket.TimeToRefill())
	
	// Consume all tokens
	bucket.TryConsume(10)
	
	// Should take 5 seconds to refill (10 tokens / 2 per second)
	timeToRefill := bucket.TimeToRefill()
	assert.True(t, timeToRefill >= 4*time.Second && timeToRefill <= 5*time.Second)
}

func TestTokenBucket_Reset(t *testing.T) {
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 1,
	}
	
	bucket := NewTokenBucket(config)
	
	// Consume some tokens
	bucket.TryConsume(5)
	assert.Equal(t, int64(5), bucket.GetTokens())
	
	// Reset bucket
	bucket.Reset()
	assert.Equal(t, int64(10), bucket.GetTokens())
}

func TestTokenBucketManager_CheckRateLimit(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockBucketStorage{}
	manager := NewTokenBucketManager(mockStorage, logger)
	defer manager.Close()
	
	config := &BucketConfig{
		Capacity:   5,
		RefillRate: 1,
	}
	
	// Mock storage calls
	mockStorage.On("LoadConfig", mock.Anything, "test_config").Return(config, nil)
	mockStorage.On("LoadBucket", mock.Anything, "test_key").Return(nil, fmt.Errorf("not found"))
	mockStorage.On("SaveBucket", mock.Anything, "test_key", mock.AnythingOfType("*ratelimit.TokenBucket")).Return(nil)
	
	ctx := context.Background()
	
	// First request should be allowed
	result, err := manager.CheckRateLimit(ctx, "test_key", 1, "test_config")
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, int64(4), result.TokensLeft) // 5 - 1 = 4
	
	mockStorage.AssertExpectations(t)
}

func TestTokenBucketManager_SetConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockBucketStorage{}
	manager := NewTokenBucketManager(mockStorage, logger)
	defer manager.Close()
	
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 2,
	}
	
	mockStorage.On("SaveConfig", mock.Anything, "test_config", config).Return(nil)
	
	ctx := context.Background()
	err := manager.SetConfig(ctx, "test_config", config)
	
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func TestTokenBucketManager_GetConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockBucketStorage{}
	manager := NewTokenBucketManager(mockStorage, logger)
	defer manager.Close()
	
	config := &BucketConfig{
		Capacity:   10,
		RefillRate: 2,
	}
	
	mockStorage.On("LoadConfig", mock.Anything, "test_config").Return(config, nil)
	
	ctx := context.Background()
	retrievedConfig, err := manager.GetConfig(ctx, "test_config")
	
	assert.NoError(t, err)
	assert.Equal(t, config, retrievedConfig)
	mockStorage.AssertExpectations(t)
}

func TestTokenBucketManager_ResetBucket(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockBucketStorage{}
	manager := NewTokenBucketManager(mockStorage, logger)
	defer manager.Close()
	
	config := &BucketConfig{
		Capacity:   5,
		RefillRate: 1,
	}
	
	// Setup mocks for initial bucket creation
	mockStorage.On("LoadConfig", mock.Anything, "test_config").Return(config, nil)
	mockStorage.On("LoadBucket", mock.Anything, "test_key").Return(nil, fmt.Errorf("not found"))
	mockStorage.On("SaveBucket", mock.Anything, "test_key", mock.AnythingOfType("*ratelimit.TokenBucket")).Return(nil)
	
	ctx := context.Background()
	
	// Create bucket by checking rate limit
	manager.CheckRateLimit(ctx, "test_key", 3, "test_config")
	
	// Reset bucket
	err := manager.ResetBucket(ctx, "test_key")
	assert.NoError(t, err)
	
	mockStorage.AssertExpectations(t)
}

func TestPerUserStrategy(t *testing.T) {
	strategy := NewPerUserStrategy("user_config")
	
	request := &RateLimitRequest{
		UserID: "user123",
		IP:     "192.168.1.1",
	}
	
	assert.Equal(t, "user:user123", strategy.GetBucketKey(request))
	assert.Equal(t, "user_config", strategy.GetConfigName(request))
	assert.Equal(t, int64(1), strategy.GetTokensRequired(request))
	assert.Equal(t, "per_user", strategy.GetStrategyName())
}

func TestPerIPStrategy(t *testing.T) {
	strategy := NewPerIPStrategy("ip_config")
	
	request := &RateLimitRequest{
		UserID: "user123",
		IP:     "192.168.1.1",
	}
	
	assert.Equal(t, "ip:192.168.1.1", strategy.GetBucketKey(request))
	assert.Equal(t, "ip_config", strategy.GetConfigName(request))
	assert.Equal(t, int64(1), strategy.GetTokensRequired(request))
	assert.Equal(t, "per_ip", strategy.GetStrategyName())
}

func TestSizeBasedStrategy(t *testing.T) {
	strategy := NewSizeBasedStrategy("size_config", 1024, 1) // 1KB per token, min 1 token
	
	tests := []struct {
		name         string
		requestSize  int64
		expectedTokens int64
	}{
		{"Small request", 512, 1},    // Less than 1KB, should use minimum
		{"Exact 1KB", 1024, 1},      // Exactly 1KB
		{"Large request", 5120, 5},  // 5KB, should require 5 tokens
		{"Zero size", 0, 1},         // Zero size, should use minimum
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &RateLimitRequest{
				UserID:      "user123",
				RequestSize: tt.requestSize,
			}
			
			tokens := strategy.GetTokensRequired(request)
			assert.Equal(t, tt.expectedTokens, tokens)
		})
	}
}

func TestTieredStrategy(t *testing.T) {
	tierConfigs := map[string]string{
		"premium": "premium_config",
		"basic":   "basic_config",
	}
	
	strategy := NewTieredStrategy(tierConfigs, "default_config")
	
	tests := []struct {
		name           string
		tier           interface{}
		expectedConfig string
	}{
		{"Premium tier", "premium", "premium_config"},
		{"Basic tier", "basic", "basic_config"},
		{"Unknown tier", "unknown", "default_config"},
		{"No tier", nil, "default_config"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[string]interface{})
			if tt.tier != nil {
				metadata["tier"] = tt.tier
			}
			
			request := &RateLimitRequest{
				UserID:   "user123",
				Metadata: metadata,
			}
			
			config := strategy.GetConfigName(request)
			assert.Equal(t, tt.expectedConfig, config)
		})
	}
}

func TestMultiLayerRateLimiter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockBucketStorage{}
	manager := NewTokenBucketManager(mockStorage, logger)
	defer manager.Close()
	
	limiter := NewMultiLayerRateLimiter(manager, logger)
	
	// Add strategies
	limiter.AddStrategy(NewPerUserStrategy("user_config"))
	limiter.AddStrategy(NewPerIPStrategy("ip_config"))
	
	// Mock storage calls
	userConfig := &BucketConfig{Capacity: 5, RefillRate: 1}
	ipConfig := &BucketConfig{Capacity: 10, RefillRate: 2}
	
	mockStorage.On("LoadConfig", mock.Anything, "user_config").Return(userConfig, nil)
	mockStorage.On("LoadConfig", mock.Anything, "ip_config").Return(ipConfig, nil)
	mockStorage.On("LoadBucket", mock.Anything, mock.AnythingOfType("string")).Return(nil, fmt.Errorf("not found"))
	mockStorage.On("SaveBucket", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*ratelimit.TokenBucket")).Return(nil)
	
	request := &RateLimitRequest{
		UserID: "user123",
		IP:     "192.168.1.1",
	}
	
	ctx := context.Background()
	result, err := limiter.CheckRateLimit(ctx, request)
	
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, result.LayerResults, 2) // Should have results from both strategies
	
	mockStorage.AssertExpectations(t)
}