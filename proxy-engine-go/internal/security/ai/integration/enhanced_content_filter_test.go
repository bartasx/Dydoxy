package integration

import (
	"context"
	"testing"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/dydoxy/proxy-engine-go/internal/security/filter"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing
type MockContentFilter struct {
	mock.Mock
}

func (m *MockContentFilter) Filter(ctx context.Context, request *filter.ContentRequest) (*filter.FilterResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*filter.FilterResult), args.Error(1)
}

func (m *MockContentFilter) AddRule(ctx context.Context, rule *filter.FilterRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockContentFilter) RemoveRule(ctx context.Context, ruleID string) error {
	args := m.Called(ctx, ruleID)
	return args.Error(0)
}

func (m *MockContentFilter) UpdateRule(ctx context.Context, rule *filter.FilterRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockContentFilter) GetRules(ctx context.Context) ([]*filter.FilterRule, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*filter.FilterRule), args.Error(1)
}

func (m *MockContentFilter) GetRulesByType(ctx context.Context, ruleType filter.RuleType) ([]*filter.FilterRule, error) {
	args := m.Called(ctx, ruleType)
	return args.Get(0).([]*filter.FilterRule), args.Error(1)
}

func (m *MockContentFilter) GetStats(ctx context.Context) (*filter.FilterStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*filter.FilterStats), args.Error(1)
}

func (m *MockContentFilter) ReloadRules(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockAIThreatDetector struct {
	mock.Mock
}

func (m *MockAIThreatDetector) AnalyzeRequest(ctx context.Context, request *ai.ThreatAnalysisRequest) (*ai.ThreatAnalysisResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*ai.ThreatAnalysisResult), args.Error(1)
}

func (m *MockAIThreatDetector) UpdateModels(ctx context.Context, trainingData []*ai.TrainingExample) error {
	args := m.Called(ctx, trainingData)
	return args.Error(0)
}

func (m *MockAIThreatDetector) GetThreatIntelligence(ctx context.Context, query *ai.ThreatQuery) (*ai.ThreatIntelligence, error) {
	args := m.Called(ctx, query)
	return args.Get(0).(*ai.ThreatIntelligence), args.Error(1)
}

func (m *MockAIThreatDetector) ConfigurePolicies(ctx context.Context, policies *ai.ThreatPolicies) error {
	args := m.Called(ctx, policies)
	return args.Error(0)
}

func (m *MockAIThreatDetector) GetStats(ctx context.Context) (*ai.AIThreatStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*ai.AIThreatStats), args.Error(1)
}

func (m *MockAIThreatDetector) GetHealth(ctx context.Context) (*ai.AIHealthStatus, error) {
	args := m.Called(ctx)
	return args.Get(0).(*ai.AIHealthStatus), args.Error(1)
}

type MockFeatureExtractor struct {
	mock.Mock
}

func (m *MockFeatureExtractor) ExtractFeatures(ctx context.Context, request *ai.ThreatAnalysisRequest) (*ai.FeatureVector, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*ai.FeatureVector), args.Error(1)
}

func (m *MockFeatureExtractor) ExtractBehavioralFeatures(ctx context.Context, subject string, request *ai.RequestContext) (map[string]float64, error) {
	args := m.Called(ctx, subject, request)
	return args.Get(0).(map[string]float64), args.Error(1)
}

func (m *MockFeatureExtractor) GetFeatureNames() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockFeatureExtractor) ValidateFeatures(features *ai.FeatureVector) error {
	args := m.Called(features)
	return args.Error(0)
}

func TestAIEnhancedContentFilter_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	assert.NotNil(t, enhancedFilter)
	assert.NotNil(t, enhancedFilter.config)
	assert.True(t, enhancedFilter.config.AIEnabled)
	assert.Equal(t, 0.7, enhancedFilter.config.ConfidenceThreshold)
	assert.NotNil(t, enhancedFilter.stats)
}

func TestAIEnhancedContentFilter_TraditionalFilterOnly(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	// Disable AI
	config := enhancedFilter.GetConfig()
	config.AIEnabled = false
	enhancedFilter.SetConfig(config)
	
	request := &filter.ContentRequest{
		URL:    "https://example.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	expectedResult := &filter.FilterResult{
		Allowed:   true,
		Action:    filter.ActionAllow,
		Reason:    "Traditional filter allowed",
		Timestamp: time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(expectedResult, nil)
	
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, expectedResult.Allowed, result.Allowed)
	assert.Equal(t, expectedResult.Action, result.Action)
	
	baseFilter.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_TraditionalBlocked(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	// Configure to not combine results
	config := enhancedFilter.GetConfig()
	config.CombineResults = false
	enhancedFilter.SetConfig(config)
	
	request := &filter.ContentRequest{
		URL:    "https://malicious.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	blockedResult := &filter.FilterResult{
		Allowed:   false,
		Action:    filter.ActionBlock,
		Reason:    "Blocked by traditional rule",
		Timestamp: time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(blockedResult, nil)
	
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, filter.ActionBlock, result.Action)
	
	// AI should not be called
	aiDetector.AssertNotCalled(t, "AnalyzeRequest")
	baseFilter.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_AIDetectsThreat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	request := &filter.ContentRequest{
		URL:    "https://suspicious.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	// Traditional filter allows
	allowedResult := &filter.FilterResult{
		Allowed:   true,
		Action:    filter.ActionAllow,
		Reason:    "No traditional rules matched",
		Timestamp: time.Now(),
	}
	
	// AI detects threat
	aiResult := &ai.ThreatAnalysisResult{
		RequestID:         "test-req",
		IsThreat:          true,
		ThreatType:        ai.ThreatTypeMalware,
		ThreatLevel:       ai.ThreatLevelHigh,
		Confidence:        0.9,
		RecommendedAction: ai.ActionBlock,
		Reason:            "AI detected malware",
		Timestamp:         time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(allowedResult, nil)
	aiDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(aiResult, nil)
	
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	
	// Should be blocked by AI
	assert.False(t, result.Allowed)
	assert.Equal(t, filter.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "AI detected malware")
	assert.NotNil(t, result.MatchedRule)
	assert.Contains(t, result.MatchedRule.Name, "AI")
	
	baseFilter.AssertExpectations(t)
	aiDetector.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_AILowConfidence(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	request := &filter.ContentRequest{
		URL:    "https://example.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	// Traditional filter allows
	allowedResult := &filter.FilterResult{
		Allowed:   true,
		Action:    filter.ActionAllow,
		Reason:    "No traditional rules matched",
		Timestamp: time.Now(),
	}
	
	// AI detects threat but with low confidence
	aiResult := &ai.ThreatAnalysisResult{
		RequestID:         "test-req",
		IsThreat:          true,
		ThreatType:        ai.ThreatTypeSuspicious,
		ThreatLevel:       ai.ThreatLevelLow,
		Confidence:        0.3, // Below threshold
		RecommendedAction: ai.ActionMonitor,
		Reason:            "Low confidence threat",
		Timestamp:         time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(allowedResult, nil)
	aiDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(aiResult, nil)
	
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	
	// Should remain allowed due to low confidence
	assert.True(t, result.Allowed)
	assert.Equal(t, filter.ActionAllow, result.Action)
	
	baseFilter.AssertExpectations(t)
	aiDetector.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_AIOverrideTraditional(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	request := &filter.ContentRequest{
		URL:    "https://example.com/admin",
		Method: "GET",
		UserID: "user123",
	}
	
	// Traditional filter blocks
	blockedResult := &filter.FilterResult{
		Allowed:   false,
		Action:    filter.ActionBlock,
		Reason:    "Blocked by admin rule",
		Timestamp: time.Now(),
	}
	
	// AI has very low confidence (likely false positive)
	aiResult := &ai.ThreatAnalysisResult{
		RequestID:         "test-req",
		IsThreat:          false,
		ThreatType:        ai.ThreatTypeSuspicious,
		ThreatLevel:       ai.ThreatLevelLow,
		Confidence:        0.1, // Very low confidence
		RecommendedAction: ai.ActionAllow,
		Reason:            "Very low threat probability",
		Timestamp:         time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(blockedResult, nil)
	aiDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(aiResult, nil)
	
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	
	// Should be allowed due to AI override
	assert.True(t, result.Allowed)
	assert.Equal(t, filter.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "AI low confidence override")
	
	baseFilter.AssertExpectations(t)
	aiDetector.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_AIError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	request := &filter.ContentRequest{
		URL:    "https://example.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	allowedResult := &filter.FilterResult{
		Allowed:   true,
		Action:    filter.ActionAllow,
		Reason:    "No traditional rules matched",
		Timestamp: time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(allowedResult, nil)
	aiDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return((*ai.ThreatAnalysisResult)(nil), assert.AnError)
	
	// Test with fallback enabled (default)
	result, err := enhancedFilter.Filter(context.Background(), request)
	require.NoError(t, err)
	assert.True(t, result.Allowed) // Should fallback to traditional result
	
	// Test with fallback disabled
	config := enhancedFilter.GetConfig()
	config.FallbackOnError = false
	enhancedFilter.SetConfig(config)
	
	result, err = enhancedFilter.Filter(context.Background(), request)
	assert.Error(t, err)
	assert.Nil(t, result)
	
	baseFilter.AssertExpectations(t)
	aiDetector.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_ThreatTypeMapping(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	enhancedFilter := NewAIEnhancedContentFilter(nil, nil, nil, logger)
	
	tests := []struct {
		name        string
		threatType  ai.ThreatType
		threatLevel ai.ThreatLevel
		expected    filter.FilterAction
	}{
		{"Malware High", ai.ThreatTypeMalware, ai.ThreatLevelHigh, filter.ActionBlock},
		{"Phishing Medium", ai.ThreatTypePhishing, ai.ThreatLevelMedium, filter.ActionBlock},
		{"Botnet Critical", ai.ThreatTypeBotnet, ai.ThreatLevelCritical, filter.ActionBlock},
		{"Data Exfiltration", ai.ThreatTypeDataExfiltration, ai.ThreatLevelMedium, filter.ActionQuarantine},
		{"Zero Day", ai.ThreatTypeZeroDay, ai.ThreatLevelHigh, filter.ActionBlock},
		{"Insider Threat", ai.ThreatTypeInsiderThreat, ai.ThreatLevelMedium, filter.ActionLog},
		{"Suspicious Low", ai.ThreatTypeSuspicious, ai.ThreatLevelLow, filter.ActionAllow},
		{"Suspicious Medium", ai.ThreatTypeSuspicious, ai.ThreatLevelMedium, filter.ActionLog},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := enhancedFilter.mapThreatToAction(tt.threatType, tt.threatLevel)
			assert.Equal(t, tt.expected, action)
		})
	}
}

func TestAIEnhancedContentFilter_Statistics(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	
	// Initial stats should be zero
	stats := enhancedFilter.GetStats()
	assert.Equal(t, int64(0), stats.TotalRequests)
	assert.Equal(t, int64(0), stats.AIAnalyzedRequests)
	
	// Process some requests
	request := &filter.ContentRequest{
		URL:    "https://example.com/test",
		Method: "GET",
		UserID: "user123",
	}
	
	allowedResult := &filter.FilterResult{
		Allowed:   true,
		Action:    filter.ActionAllow,
		Reason:    "No rules matched",
		Timestamp: time.Now(),
	}
	
	aiResult := &ai.ThreatAnalysisResult{
		RequestID:  "test-req",
		IsThreat:   false,
		Confidence: 0.2,
		Timestamp:  time.Now(),
	}
	
	baseFilter.On("Filter", mock.Anything, request).Return(allowedResult, nil).Times(3)
	aiDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(aiResult, nil).Times(3)
	
	// Process 3 requests
	for i := 0; i < 3; i++ {
		_, err := enhancedFilter.Filter(context.Background(), request)
		require.NoError(t, err)
	}
	
	// Check updated stats
	stats = enhancedFilter.GetStats()
	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.Equal(t, int64(3), stats.AIAnalyzedRequests)
	assert.Equal(t, int64(3), stats.AIAllowedRequests)
	assert.Equal(t, int64(0), stats.AIBlockedRequests)
	assert.Greater(t, stats.AverageProcessingTime, time.Duration(0))
	
	// Reset stats
	enhancedFilter.ResetStats()
	stats = enhancedFilter.GetStats()
	assert.Equal(t, int64(0), stats.TotalRequests)
	
	baseFilter.AssertExpectations(t)
	aiDetector.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_PassThroughMethods(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	baseFilter := &MockContentFilter{}
	aiDetector := &MockAIThreatDetector{}
	featureExtractor := &MockFeatureExtractor{}
	
	enhancedFilter := NewAIEnhancedContentFilter(baseFilter, aiDetector, featureExtractor, logger)
	ctx := context.Background()
	
	// Test AddRule
	rule := &filter.FilterRule{ID: "test-rule", Name: "Test Rule"}
	baseFilter.On("AddRule", ctx, rule).Return(nil)
	err := enhancedFilter.AddRule(ctx, rule)
	assert.NoError(t, err)
	
	// Test RemoveRule
	baseFilter.On("RemoveRule", ctx, "test-rule").Return(nil)
	err = enhancedFilter.RemoveRule(ctx, "test-rule")
	assert.NoError(t, err)
	
	// Test UpdateRule
	baseFilter.On("UpdateRule", ctx, rule).Return(nil)
	err = enhancedFilter.UpdateRule(ctx, rule)
	assert.NoError(t, err)
	
	// Test GetRules
	rules := []*filter.FilterRule{rule}
	baseFilter.On("GetRules", ctx).Return(rules, nil)
	returnedRules, err := enhancedFilter.GetRules(ctx)
	assert.NoError(t, err)
	assert.Equal(t, rules, returnedRules)
	
	// Test ReloadRules
	baseFilter.On("ReloadRules", ctx).Return(nil)
	err = enhancedFilter.ReloadRules(ctx)
	assert.NoError(t, err)
	
	baseFilter.AssertExpectations(t)
}

func TestAIEnhancedContentFilter_ConfigurationManagement(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	enhancedFilter := NewAIEnhancedContentFilter(nil, nil, nil, logger)
	
	// Test default configuration
	config := enhancedFilter.GetConfig()
	assert.True(t, config.AIEnabled)
	assert.Equal(t, 0.7, config.ConfidenceThreshold)
	assert.True(t, config.FallbackOnError)
	assert.Equal(t, 50*time.Millisecond, config.MaxProcessingTime)
	
	// Test updating configuration
	newConfig := &AIFilterConfig{
		AIEnabled:           false,
		ConfidenceThreshold: 0.8,
		FallbackOnError:     false,
		MaxProcessingTime:   100 * time.Millisecond,
		LogAIDecisions:      false,
		CombineResults:      false,
	}
	
	enhancedFilter.SetConfig(newConfig)
	updatedConfig := enhancedFilter.GetConfig()
	
	assert.False(t, updatedConfig.AIEnabled)
	assert.Equal(t, 0.8, updatedConfig.ConfidenceThreshold)
	assert.False(t, updatedConfig.FallbackOnError)
	assert.Equal(t, 100*time.Millisecond, updatedConfig.MaxProcessingTime)
	assert.False(t, updatedConfig.LogAIDecisions)
	assert.False(t, updatedConfig.CombineResults)
}