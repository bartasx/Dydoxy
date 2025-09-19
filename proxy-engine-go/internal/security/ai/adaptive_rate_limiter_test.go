package ai

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"../../ratelimit"
)

// Mock MultiLayerRateLimiter for testing
type MockMultiLayerRateLimiter struct {
	mock.Mock
}

func (m *MockMultiLayerRateLimiter) CheckRateLimit(ctx context.Context, request *ratelimit.RateLimitRequest) (*ratelimit.MultiLayerResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*ratelimit.MultiLayerResult), args.Error(1)
}

func (m *MockMultiLayerRateLimiter) AddStrategy(strategy ratelimit.RateLimitStrategy) {
	m.Called(strategy)
}

func TestAIAdaptiveRateLimiter_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	bucketManager := &ratelimit.TokenBucketManager{}
	userOrgManager := &ratelimit.UserOrgLimitManager{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, bucketManager, userOrgManager, logger)
	
	assert.NotNil(t, limiter)
	assert.NotNil(t, limiter.config)
	assert.NotNil(t, limiter.stats)
	assert.True(t, limiter.config.Enabled)
	assert.NotEmpty(t, limiter.config.ThreatMultipliers)
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_Disabled(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	// Disable adaptive rate limiting
	config := limiter.GetConfig()
	config.Enabled = false
	limiter.SetConfig(config)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID: "user123",
			IP:     "192.168.1.1",
		},
	}
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: true,
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, request.RateLimitRequest).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.True(t, result.Allowed)
	assert.Equal(t, 1.0, result.AppliedMultiplier)
	assert.Equal(t, "ai_disabled", result.AdjustmentReason)
	
	multiLayerLimiter.AssertExpectations(t)
	threatDetector.AssertNotCalled(t, "AnalyzeRequest")
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_Whitelisted(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	// Add user to whitelist
	config := limiter.GetConfig()
	config.WhitelistedUsers = []string{"whitelisted_user"}
	limiter.SetConfig(config)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID: "whitelisted_user",
			IP:     "192.168.1.1",
		},
	}
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: true,
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, request.RateLimitRequest).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.True(t, result.Allowed)
	assert.Equal(t, 1.0, result.AppliedMultiplier)
	assert.Equal(t, "whitelisted", result.AdjustmentReason)
	
	multiLayerLimiter.AssertExpectations(t)
	threatDetector.AssertNotCalled(t, "AnalyzeRequest")
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_NoThreat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID:    "user123",
			IP:        "192.168.1.1",
			Timestamp: time.Now(),
		},
	}
	
	// Mock threat analysis - no threat
	threatAnalysis := &ThreatAnalysisResult{
		RequestID:   "test-req-123",
		IsThreat:    false,
		ThreatType:  ThreatTypeNone,
		ThreatLevel: ThreatLevelNone,
		Confidence:  0.1,
		Timestamp:   time.Now(),
	}
	
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(threatAnalysis, nil)
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: true,
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, mock.AnythingOfType("*ratelimit.RateLimitRequest")).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.True(t, result.Allowed)
	assert.Equal(t, 1.0, result.AppliedMultiplier)
	assert.Equal(t, "standard", result.AdjustmentReason)
	assert.False(t, result.CacheHit)
	assert.NotNil(t, result.ThreatAnalysis)
	
	threatDetector.AssertExpectations(t)
	multiLayerLimiter.AssertExpectations(t)
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_HighThreat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID:      "user123",
			IP:          "192.168.1.1",
			RequestSize: 1024,
			Timestamp:   time.Now(),
		},
	}
	
	// Mock threat analysis - high threat
	threatAnalysis := &ThreatAnalysisResult{
		RequestID:   "test-req-456",
		IsThreat:    true,
		ThreatType:  ThreatTypeMalware,
		ThreatLevel: ThreatLevelHigh,
		Confidence:  0.9,
		Timestamp:   time.Now(),
	}
	
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(threatAnalysis, nil)
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: false,
		DeniedBy: "threat_based",
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, mock.AnythingOfType("*ratelimit.RateLimitRequest")).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.False(t, result.Allowed)
	assert.Greater(t, result.AppliedMultiplier, 1.0) // Should be stricter for threats
	assert.Contains(t, result.AdjustmentReason, "threat_level_high")
	assert.Contains(t, result.AdjustmentReason, "threat_type_malware")
	assert.NotNil(t, result.ThreatAnalysis)
	assert.Equal(t, ThreatTypeMalware, result.ThreatAnalysis.ThreatType)
	
	threatDetector.AssertExpectations(t)
	multiLayerLimiter.AssertExpectations(t)
	
	// Check statistics
	stats := limiter.GetStats()
	assert.Equal(t, int64(1), stats.RequestsProcessed)
	assert.Equal(t, int64(1), stats.ThreatBasedAdjustments)
	assert.Equal(t, int64(1), stats.AdjustmentsByThreatLevel[ThreatLevelHigh])
	assert.Equal(t, int64(1), stats.AdjustmentsByThreatType[ThreatTypeMalware])
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_WithProvidedAnalysis(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	// Provide threat analysis directly
	threatAnalysis := &ThreatAnalysisResult{
		RequestID:   "test-req-789",
		IsThreat:    true,
		ThreatType:  ThreatTypePhishing,
		ThreatLevel: ThreatLevelMedium,
		Confidence:  0.7,
		Timestamp:   time.Now(),
	}
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID:    "user123",
			IP:        "192.168.1.1",
			Timestamp: time.Now(),
		},
		ThreatAnalysis:  threatAnalysis,
		ReputationScore: 0.3,
	}
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: false,
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, mock.AnythingOfType("*ratelimit.RateLimitRequest")).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.False(t, result.Allowed)
	assert.Greater(t, result.AppliedMultiplier, 1.0)
	assert.Equal(t, 0.3, result.ReputationScore)
	assert.Equal(t, threatAnalysis, result.ThreatAnalysis)
	
	// Threat detector should not be called since analysis was provided
	threatDetector.AssertNotCalled(t, "AnalyzeRequest")
	multiLayerLimiter.AssertExpectations(t)
}

func TestAIAdaptiveRateLimiter_CheckAdaptiveRateLimit_ThreatAnalysisError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID:    "user123",
			IP:        "192.168.1.1",
			Timestamp: time.Now(),
		},
	}
	
	// Mock threat analysis error
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(nil, assert.AnError)
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: true,
	}
	
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, request.RateLimitRequest).Return(standardResult, nil)
	
	result, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	assert.True(t, result.Allowed)
	assert.Equal(t, 1.0, result.AppliedMultiplier)
	assert.Equal(t, "threat_analysis_failed", result.AdjustmentReason)
	
	threatDetector.AssertExpectations(t)
	multiLayerLimiter.AssertExpectations(t)
}

func TestAIAdaptiveRateLimiter_CalculateAdaptiveMultiplier(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	tests := []struct {
		name           string
		threatInfo     *CachedThreatInfo
		expectedMin    float64
		expectedMax    float64
		expectedReason string
	}{
		{
			name: "no threat",
			threatInfo: &CachedThreatInfo{
				ThreatAnalysis: &ThreatAnalysisResult{
					IsThreat: false,
				},
				ReputationScore: 0.8,
			},
			expectedMin:    0.4,
			expectedMax:    0.6,
			expectedReason: "reputation",
		},
		{
			name: "critical threat",
			threatInfo: &CachedThreatInfo{
				ThreatAnalysis: &ThreatAnalysisResult{
					IsThreat:    true,
					ThreatLevel: ThreatLevelCritical,
					ThreatType:  ThreatTypeMalware,
				},
				ReputationScore: 0.1,
			},
			expectedMin:    10.0, // Should hit max bound
			expectedMax:    10.0,
			expectedReason: "threat_level_critical",
		},
		{
			name: "medium threat with violations",
			threatInfo: &CachedThreatInfo{
				ThreatAnalysis: &ThreatAnalysisResult{
					IsThreat:    true,
					ThreatLevel: ThreatLevelMedium,
					ThreatType:  ThreatTypeSuspicious,
				},
				ReputationScore: 0.3,
				ViolationCount:  2,
			},
			expectedMin:    4.0,
			expectedMax:    10.0,
			expectedReason: "progressive_penalty",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multiplier, reason := limiter.calculateAdaptiveMultiplier(tt.threatInfo)
			
			assert.GreaterOrEqual(t, multiplier, tt.expectedMin)
			assert.LessOrEqual(t, multiplier, tt.expectedMax)
			assert.Contains(t, reason, tt.expectedReason)
		})
	}
}

func TestAIAdaptiveRateLimiter_ApplyAdaptiveMultiplier(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	originalRequest := &ratelimit.RateLimitRequest{
		UserID:      "user123",
		RequestSize: 1000,
		Metadata:    map[string]interface{}{"original": true},
	}
	
	// Test with multiplier > 1 (stricter)
	adaptedRequest := limiter.applyAdaptiveMultiplier(originalRequest, 2.0)
	assert.Equal(t, int64(2000), adaptedRequest.RequestSize)
	assert.Equal(t, 2.0, adaptedRequest.Metadata["ai_multiplier"])
	assert.Equal(t, true, adaptedRequest.Metadata["ai_adapted"])
	assert.Equal(t, true, adaptedRequest.Metadata["original"]) // Original metadata preserved
	
	// Test with multiplier < 1 (more lenient)
	adaptedRequest = limiter.applyAdaptiveMultiplier(originalRequest, 0.5)
	assert.Equal(t, int64(500), adaptedRequest.RequestSize)
	assert.Equal(t, 0.5, adaptedRequest.Metadata["ai_multiplier"])
	
	// Test with multiplier = 1 (no change)
	adaptedRequest = limiter.applyAdaptiveMultiplier(originalRequest, 1.0)
	assert.Equal(t, originalRequest, adaptedRequest) // Should return same instance
}

func TestAIAdaptiveRateLimiter_ThreatCache(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	multiLayerLimiter := &MockMultiLayerRateLimiter{}
	
	limiter := NewAIAdaptiveRateLimiter(threatDetector, multiLayerLimiter, nil, nil, logger)
	
	// Set short cache timeout for testing
	config := limiter.GetConfig()
	config.ThreatCacheTimeout = 100 * time.Millisecond
	limiter.SetConfig(config)
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID:    "user123",
			IP:        "192.168.1.1",
			Timestamp: time.Now(),
		},
	}
	
	threatAnalysis := &ThreatAnalysisResult{
		RequestID: "test-req-cache",
		IsThreat:  false,
		Timestamp: time.Now(),
	}
	
	standardResult := &ratelimit.MultiLayerResult{
		Allowed: true,
	}
	
	// First call should trigger threat analysis
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(threatAnalysis, nil).Once()
	multiLayerLimiter.On("CheckRateLimit", mock.Anything, mock.AnythingOfType("*ratelimit.RateLimitRequest")).Return(standardResult, nil).Twice()
	
	// First request
	result1, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result1.CacheHit)
	
	// Second request (should hit cache)
	result2, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.True(t, result2.CacheHit)
	
	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)
	
	// Third request (cache expired, should trigger new analysis)
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(threatAnalysis, nil).Once()
	result3, err := limiter.CheckAdaptiveRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result3.CacheHit)
	
	threatDetector.AssertExpectations(t)
	multiLayerLimiter.AssertExpectations(t)
}

func TestAIAdaptiveRateLimiter_EmergencyMode(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	// Initially not in emergency mode
	config := limiter.GetConfig()
	assert.False(t, config.EmergencyMode)
	
	// Activate emergency mode
	limiter.ActivateEmergencyMode("test activation")
	
	config = limiter.GetConfig()
	assert.True(t, config.EmergencyMode)
	
	stats := limiter.GetStats()
	assert.Equal(t, int64(1), stats.EmergencyModeActivations)
	assert.False(t, stats.LastEmergencyMode.IsZero())
	
	// Deactivate emergency mode
	limiter.DeactivateEmergencyMode()
	
	config = limiter.GetConfig()
	assert.False(t, config.EmergencyMode)
}

func TestAIAdaptiveRateLimiter_ReputationCalculation(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	request := &ratelimit.RateLimitRequest{
		UserID: "user123",
	}
	
	tests := []struct {
		name           string
		analysis       *ThreatAnalysisResult
		expectedMin    float64
		expectedMax    float64
	}{
		{
			name: "no threat, low confidence",
			analysis: &ThreatAnalysisResult{
				IsThreat:   false,
				Confidence: 0.1,
			},
			expectedMin: 0.7,
			expectedMax: 1.0,
		},
		{
			name: "threat, high confidence",
			analysis: &ThreatAnalysisResult{
				IsThreat:   true,
				Confidence: 0.9,
			},
			expectedMin: 0.0,
			expectedMax: 0.2,
		},
		{
			name: "threat, medium confidence",
			analysis: &ThreatAnalysisResult{
				IsThreat:   true,
				Confidence: 0.5,
			},
			expectedMin: 0.2,
			expectedMax: 0.4,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := limiter.calculateReputationScore(request, tt.analysis)
			assert.GreaterOrEqual(t, score, tt.expectedMin)
			assert.LessOrEqual(t, score, tt.expectedMax)
		})
	}
}

func TestAIAdaptiveRateLimiter_ReputationMultiplier(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	tests := []struct {
		reputation float64
		expected   float64
	}{
		{0.9, 0.5}, // High reputation = lenient
		{0.7, 0.8}, // Good reputation = somewhat lenient
		{0.5, 1.0}, // Neutral reputation = standard
		{0.3, 1.5}, // Poor reputation = stricter
		{0.1, 2.0}, // Very poor reputation = very strict
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("reputation_%.1f", tt.reputation), func(t *testing.T) {
			multiplier := limiter.calculateReputationMultiplier(tt.reputation)
			assert.Equal(t, tt.expected, multiplier)
		})
	}
}

func TestAIAdaptiveRateLimiter_Statistics(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	// Initial stats
	stats := limiter.GetStats()
	assert.Equal(t, int64(0), stats.RequestsProcessed)
	assert.Equal(t, 1.0, stats.AverageMultiplier)
	
	// Simulate processing requests
	analysis1 := &ThreatAnalysisResult{
		IsThreat:    true,
		ThreatLevel: ThreatLevelHigh,
		ThreatType:  ThreatTypeMalware,
	}
	
	analysis2 := &ThreatAnalysisResult{
		IsThreat: false,
	}
	
	limiter.updateStats(analysis1, 3.0, false)
	limiter.updateStats(analysis2, 1.0, true)
	
	stats = limiter.GetStats()
	assert.Equal(t, int64(2), stats.RequestsProcessed)
	assert.Greater(t, stats.AverageMultiplier, 1.0)
	assert.Greater(t, stats.CacheHitRate, 0.0)
	assert.Less(t, stats.CacheHitRate, 1.0)
	
	// Test stats reset
	limiter.ResetStats()
	stats = limiter.GetStats()
	assert.Equal(t, int64(0), stats.RequestsProcessed)
	assert.Equal(t, 1.0, stats.AverageMultiplier)
}

func TestAIAdaptiveRateLimiter_Configuration(t *testing.T) {
	logger := logrus.New()
	limiter := NewAIAdaptiveRateLimiter(nil, nil, nil, nil, logger)
	
	// Test default configuration
	config := limiter.GetConfig()
	assert.True(t, config.Enabled)
	assert.True(t, config.ThreatBasedAdjustment)
	assert.NotEmpty(t, config.ThreatMultipliers)
	
	// Test configuration update
	newConfig := &AdaptiveRateLimitConfig{
		Enabled:               false,
		ThreatBasedAdjustment: false,
		ThreatMultipliers: map[ThreatLevel]float64{
			ThreatLevelHigh: 2.0,
		},
		MinRateLimitMultiplier: 0.5,
		MaxRateLimitMultiplier: 5.0,
	}
	
	limiter.SetConfig(newConfig)
	updatedConfig := limiter.GetConfig()
	
	assert.False(t, updatedConfig.Enabled)
	assert.False(t, updatedConfig.ThreatBasedAdjustment)
	assert.Equal(t, 2.0, updatedConfig.ThreatMultipliers[ThreatLevelHigh])
	assert.Equal(t, 0.5, updatedConfig.MinRateLimitMultiplier)
	assert.Equal(t, 5.0, updatedConfig.MaxRateLimitMultiplier)
}