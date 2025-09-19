package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAISecurityMiddleware_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	assert.NotNil(t, middleware)
	assert.NotNil(t, middleware.config)
	assert.NotNil(t, middleware.stats)
	assert.True(t, middleware.config.Enabled)
	assert.Equal(t, 0.7, middleware.config.ThreatThreshold)
}

func TestAISecurityMiddleware_Handler_Disabled(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Disable middleware
	config := middleware.GetConfig()
	config.Enabled = false
	middleware.SetConfig(config)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Threat detector should not have been called
	threatDetector.AssertNotCalled(t, "AnalyzeRequest")
}

func TestAISecurityMiddleware_Handler_WhitelistedPath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	
	// Make request to whitelisted path
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Threat detector should not have been called
	threatDetector.AssertNotCalled(t, "AnalyzeRequest")
}

func TestAISecurityMiddleware_Handler_NoThreat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Mock threat analysis result - no threat
	result := &ThreatAnalysisResult{
		RequestID:   "test-req-123",
		IsThreat:    false,
		ThreatType:  ThreatTypeNone,
		ThreatLevel: ThreatLevelNone,
		Confidence:  0.1,
		Timestamp:   time.Now(),
	}
	
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(result, nil)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		// Check that threat info was added to context
		threatInfo, exists := c.Get("ai_threat_analysis")
		assert.True(t, exists)
		assert.Equal(t, result, threatInfo)
		
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test-req-123", w.Header().Get("X-AI-Analysis-ID"))
	assert.Equal(t, "0.100", w.Header().Get("X-AI-Threat-Score"))
	assert.Empty(t, w.Header().Get("X-AI-Threat-Detected"))
	
	threatDetector.AssertExpectations(t)
	
	// Check statistics
	stats := middleware.GetStats()
	assert.Equal(t, int64(1), stats.RequestsProcessed)
	assert.Equal(t, int64(0), stats.ThreatsDetected)
}

func TestAISecurityMiddleware_Handler_ThreatBlocked(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Mock threat analysis result - high threat
	result := &ThreatAnalysisResult{
		RequestID:   "test-req-456",
		IsThreat:    true,
		ThreatType:  ThreatTypeMalware,
		ThreatLevel: ThreatLevelHigh,
		Confidence:  0.9,
		Reasons:     []string{"Malicious payload detected"},
		Timestamp:   time.Now(),
	}
	
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(result, nil)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		// This should not be reached
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "malicious-agent")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusForbidden, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Equal(t, "Request blocked by security system", response["error"])
	assert.Equal(t, string(ThreatTypeMalware), response["threat_type"])
	assert.Equal(t, "test-req-456", response["request_id"])
	
	threatDetector.AssertExpectations(t)
	
	// Check statistics
	stats := middleware.GetStats()
	assert.Equal(t, int64(1), stats.RequestsProcessed)
	assert.Equal(t, int64(1), stats.ThreatsDetected)
	assert.Equal(t, int64(1), stats.RequestsBlocked)
	assert.Equal(t, int64(1), stats.ThreatsByLevel[ThreatLevelHigh])
	assert.Equal(t, int64(1), stats.ThreatsByType[ThreatTypeMalware])
}

func TestAISecurityMiddleware_Handler_ThreatChallenged(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Mock threat analysis result - medium threat
	result := &ThreatAnalysisResult{
		RequestID:   "test-req-789",
		IsThreat:    true,
		ThreatType:  ThreatTypeSuspicious,
		ThreatLevel: ThreatLevelMedium,
		Confidence:  0.6,
		Reasons:     []string{"Suspicious behavior pattern"},
		Timestamp:   time.Now(),
	}
	
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(result, nil)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		// This should not be reached
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Challenge-Required"))
	assert.NotEmpty(t, w.Header().Get("X-Challenge-Token"))
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Equal(t, true, response["challenge_required"])
	assert.NotEmpty(t, response["challenge_token"])
	assert.Equal(t, "test-req-789", response["request_id"])
	
	threatDetector.AssertExpectations(t)
	
	// Check statistics
	stats := middleware.GetStats()
	assert.Equal(t, int64(1), stats.RequestsProcessed)
	assert.Equal(t, int64(1), stats.ThreatsDetected)
	assert.Equal(t, int64(1), stats.RequestsChallenged)
}

func TestAISecurityMiddleware_Handler_AnalysisError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	
	// Mock analysis error
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(nil, assert.AnError)
	
	// Setup Gin
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	// Should allow request on analysis error
	assert.Equal(t, http.StatusOK, w.Code)
	
	threatDetector.AssertExpectations(t)
}

func TestAISecurityMiddleware_CreateThreatAnalysisRequest(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	// Setup Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// Create request with body
	body := []byte(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test?param=value", bytes.NewReader(body))
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	req.Header.Set("Referer", "https://example.com")
	c.Request = req
	
	analysisRequest := middleware.createThreatAnalysisRequest(c)
	
	assert.NotEmpty(t, analysisRequest.RequestID)
	assert.Equal(t, "POST", analysisRequest.Method)
	assert.Equal(t, "/api/test?param=value", analysisRequest.URL)
	assert.Equal(t, "test-agent/1.0", analysisRequest.UserAgent)
	assert.Equal(t, "user123", analysisRequest.UserID)
	assert.Equal(t, "session456", analysisRequest.SessionID)
	assert.Equal(t, "application/json", analysisRequest.Headers["Content-Type"])
	assert.Equal(t, "https://example.com", analysisRequest.Metadata["referer"])
}

func TestAISecurityMiddleware_DetermineResponseAction(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	tests := []struct {
		name           string
		result         *ThreatAnalysisResult
		expectedAction ResponseAction
	}{
		{
			name: "no threat",
			result: &ThreatAnalysisResult{
				IsThreat: false,
			},
			expectedAction: ActionAllow,
		},
		{
			name: "critical threat",
			result: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatLevel: ThreatLevelCritical,
			},
			expectedAction: ActionBlock,
		},
		{
			name: "high threat",
			result: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatLevel: ThreatLevelHigh,
			},
			expectedAction: ActionBlock,
		},
		{
			name: "medium threat",
			result: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatLevel: ThreatLevelMedium,
			},
			expectedAction: ActionChallenge,
		},
		{
			name: "low threat",
			result: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatLevel: ThreatLevelLow,
			},
			expectedAction: ActionLog,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := middleware.determineResponseAction(tt.result)
			assert.Equal(t, tt.expectedAction, action)
		})
	}
}

func TestAISecurityMiddleware_CustomResponseActions(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	// Set custom response actions
	config := middleware.GetConfig()
	config.ResponseActions[ThreatLevelHigh] = string(ActionChallenge)
	middleware.SetConfig(config)
	
	result := &ThreatAnalysisResult{
		IsThreat:    true,
		ThreatLevel: ThreatLevelHigh,
	}
	
	action := middleware.determineResponseAction(result)
	assert.Equal(t, ActionChallenge, action)
}

func TestAISecurityMiddleware_WhitelistChecks(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	// Test path whitelisting
	assert.True(t, middleware.isPathWhitelisted("/health"))
	assert.True(t, middleware.isPathWhitelisted("/health/check"))
	assert.False(t, middleware.isPathWhitelisted("/api/test"))
	
	// Test IP whitelisting
	assert.True(t, middleware.isIPWhitelisted("127.0.0.1"))
	assert.True(t, middleware.isIPWhitelisted("::1"))
	assert.False(t, middleware.isIPWhitelisted("192.168.1.1"))
}

func TestAISecurityMiddleware_Statistics(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	// Initial stats should be empty
	stats := middleware.GetStats()
	assert.Equal(t, int64(0), stats.RequestsProcessed)
	assert.Equal(t, int64(0), stats.ThreatsDetected)
	
	// Simulate processing requests
	result1 := &ThreatAnalysisResult{
		IsThreat:    true,
		ThreatLevel: ThreatLevelHigh,
		ThreatType:  ThreatTypeMalware,
	}
	
	result2 := &ThreatAnalysisResult{
		IsThreat: false,
	}
	
	middleware.updateStats(result1, 100*time.Millisecond)
	middleware.updateStats(result2, 50*time.Millisecond)
	
	stats = middleware.GetStats()
	assert.Equal(t, int64(2), stats.RequestsProcessed)
	assert.Equal(t, int64(1), stats.ThreatsDetected)
	assert.Equal(t, int64(1), stats.ThreatsByLevel[ThreatLevelHigh])
	assert.Equal(t, int64(1), stats.ThreatsByType[ThreatTypeMalware])
	assert.Greater(t, stats.AverageAnalysisTime, time.Duration(0))
	
	// Test stats reset
	middleware.ResetStats()
	stats = middleware.GetStats()
	assert.Equal(t, int64(0), stats.RequestsProcessed)
	assert.Equal(t, int64(0), stats.ThreatsDetected)
}

func TestAISecurityMiddleware_Configuration(t *testing.T) {
	logger := logrus.New()
	middleware := NewAISecurityMiddleware(nil, logger)
	
	// Test default configuration
	config := middleware.GetConfig()
	assert.True(t, config.Enabled)
	assert.Equal(t, 0.7, config.ThreatThreshold)
	assert.True(t, config.BlockingEnabled)
	
	// Test configuration update
	newConfig := &MiddlewareConfig{
		Enabled:         false,
		ThreatThreshold: 0.5,
		BlockingEnabled: false,
		ResponseActions: map[ThreatLevel]string{
			ThreatLevelHigh: string(ActionLog),
		},
	}
	
	middleware.SetConfig(newConfig)
	updatedConfig := middleware.GetConfig()
	
	assert.False(t, updatedConfig.Enabled)
	assert.Equal(t, 0.5, updatedConfig.ThreatThreshold)
	assert.False(t, updatedConfig.BlockingEnabled)
	assert.Equal(t, string(ActionLog), updatedConfig.ResponseActions[ThreatLevelHigh])
}

func TestAISecurityMiddleware_UtilityFunctions(t *testing.T) {
	// Test generateRequestID
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req
	
	requestID1 := generateRequestID(c)
	requestID2 := generateRequestID(c)
	
	assert.NotEmpty(t, requestID1)
	assert.NotEmpty(t, requestID2)
	assert.NotEqual(t, requestID1, requestID2) // Should be unique
	
	// Test convertHeaders
	headers := http.Header{
		"Content-Type":   []string{"application/json", "charset=utf-8"},
		"Authorization":  []string{"Bearer token123"},
		"X-Custom-Header": []string{"value1", "value2"},
	}
	
	converted := convertHeaders(headers)
	assert.Equal(t, "application/json", converted["Content-Type"]) // Should take first value
	assert.Equal(t, "Bearer token123", converted["Authorization"])
	assert.Equal(t, "value1", converted["X-Custom-Header"])
}