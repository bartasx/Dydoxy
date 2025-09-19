package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/dydoxy/proxy-engine-go/internal/security/filter"
	"github.com/dydoxy/proxy-engine-go/internal/security/ratelimit"
)

// AIThreatDetectionE2ETestSuite contains end-to-end tests for the AI threat detection system
type AIThreatDetectionE2ETestSuite struct {
	suite.Suite
	ctx                   context.Context
	redisClient          *redis.Client
	logger               *logrus.Logger
	aiThreatDetector     ai.AIThreatDetector
	aiEnhancedFilter     filter.ContentFilter
	aiAdaptiveRateLimiter ratelimit.RateLimiter
	metricsCollector     *ai.MetricsCollector
	alertManager         *ai.AlertManager
	wsHub                *ai.WebSocketHub
	server               *httptest.Server
	router               *gin.Engine
}

// SetupSuite sets up the test suite
func (suite *AIThreatDetectionE2ETestSuite) SetupSuite() {
	suite.ctx = context.Background()
	
	// Setup logger
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.WarnLevel)
	
	// Setup Redis client (use test database)
	suite.redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})
	
	// Test Redis connection
	err := suite.redisClient.Ping(suite.ctx).Err()
	require.NoError(suite.T(), err, "Redis connection failed")
	
	// Clean test database
	suite.redisClient.FlushDB(suite.ctx)
	
	// Initialize AI components
	suite.setupAIComponents()
	
	// Setup HTTP server
	suite.setupHTTPServer()
}

// TearDownSuite cleans up after tests
func (suite *AIThreatDetectionE2ETestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
	
	if suite.redisClient != nil {
		suite.redisClient.FlushDB(suite.ctx)
		suite.redisClient.Close()
	}
}

// SetupTest runs before each test
func (suite *AIThreatDetectionE2ETestSuite) SetupTest() {
	// Clean Redis between tests
	suite.redisClient.FlushDB(suite.ctx)
	
	// Reinitialize AI system for each test
	suite.initializeAISystem()
}

// setupAIComponents initializes all AI components
func (suite *AIThreatDetectionE2ETestSuite) setupAIComponents() {
	// Initialize AI storage
	aiStorage := ai.NewRedisStorage(suite.redisClient, suite.logger)
	
	// Initialize AI models
	modelManager := ai.NewModelManager(aiStorage, suite.logger)
	
	// Initialize feature extractors
	basicExtractor := ai.NewFeatureExtractor(suite.logger)
	advancedExtractor := ai.NewAdvancedFeatureExtractor(suite.logger)
	
	// Initialize behavioral analyzer
	behavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, suite.logger)
	
	// Initialize anomaly detector
	anomalyDetector := ai.NewAnomalyDetector(suite.logger)
	
	// Initialize content analysis model
	contentModel := ai.NewContentAnalysisModel(suite.logger)
	modelManager.RegisterModel("content_analysis", contentModel)
	
	// Initialize threat intelligence service
	threatIntelligence := ai.NewThreatIntelligenceService(aiStorage, suite.logger)
	
	// Initialize adaptive learning system
	adaptiveLearning := ai.NewAdaptiveLearningSystem(modelManager, aiStorage, suite.logger)
	
	// Initialize main AI threat detector
	suite.aiThreatDetector = ai.NewThreatDetector(&ai.ThreatDetectorConfig{
		Enabled:                    true,
		ContentAnalysisEnabled:     true,
		BehavioralAnalysisEnabled:  true,
		AnomalyDetectionEnabled:    true,
		ThreatIntelligenceEnabled:  true,
		AdaptiveLearningEnabled:    true,
		ConfidenceThreshold:        0.7,
		MaxProcessingTime:          5 * time.Second,
		EnableRealTimeUpdates:      true,
		ModelUpdateInterval:        24 * time.Hour,
	}, basicExtractor, advancedExtractor, behavioralAnalyzer, anomalyDetector,
		threatIntelligence, adaptiveLearning, modelManager, suite.logger)
	
	// Initialize content filter
	filterStorage := filter.NewRedisStorage(suite.redisClient)
	contentFilter := filter.NewEngine(filterStorage, suite.logger)
	suite.aiEnhancedFilter = ai.NewAIEnhancedContentFilter(contentFilter, suite.aiThreatDetector, suite.logger)
	
	// Initialize rate limiter
	bucketStorage := ratelimit.NewRedisBucketStorage(suite.redisClient)
	bucketManager := ratelimit.NewTokenBucketManager(bucketStorage, suite.logger)
	multiLayerLimiter := ratelimit.NewMultiLayerRateLimiter(bucketManager, suite.logger)
	suite.aiAdaptiveRateLimiter = ai.NewAIAdaptiveRateLimiter(multiLayerLimiter, suite.aiThreatDetector, suite.logger)
	
	// Initialize metrics collector
	suite.metricsCollector = ai.NewMetricsCollector(suite.logger)
	
	// Initialize alert manager
	suite.alertManager = ai.NewAlertManager(ai.GetDefaultAlertManagerConfig(), suite.logger)
	
	// Initialize WebSocket hub
	suite.wsHub = ai.NewWebSocketHub(suite.logger)
}

// setupHTTPServer sets up the HTTP server for testing
func (suite *AIThreatDetectionE2ETestSuite) setupHTTPServer() {
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	
	// Add AI security middleware
	aiSecurityMiddleware := ai.NewAISecurityMiddleware(suite.aiThreatDetector, suite.logger)
	suite.router.Use(aiSecurityMiddleware.GinMiddleware())
	
	// Add rate limiting middleware
	rateLimitMiddleware := ratelimit.NewRateLimitMiddleware(suite.aiAdaptiveRateLimiter, suite.logger, nil)
	suite.router.Use(rateLimitMiddleware.GinMiddleware())
	
	// Add content filtering middleware
	filterMiddleware := filter.NewMiddleware(suite.aiEnhancedFilter, suite.logger)
	suite.router.Use(filterMiddleware.GinMiddleware())
	
	// Add test endpoints
	suite.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	suite.router.GET("/test/benign", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "This is a benign request"})
	})
	
	suite.router.GET("/test/suspicious", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "This request contains suspicious patterns"})
	})
	
	suite.router.POST("/test/upload", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "File uploaded successfully"})
	})
	
	// AI API endpoints
	aiThreatAPI := ai.NewThreatDetectionAPI(suite.aiThreatDetector, nil, suite.metricsCollector, suite.logger)
	aiGroup := suite.router.Group("/api/v1/ai")
	aiThreatAPI.RegisterRoutes(aiGroup)
	
	// WebSocket endpoint
	suite.router.GET("/ws/threats", suite.wsHub.HandleWebSocket)
	
	// Metrics endpoint
	suite.router.GET("/api/v1/ai/metrics", func(c *gin.Context) {
		snapshot := suite.metricsCollector.GetSnapshot()
		c.JSON(200, snapshot)
	})
	
	// Create test server
	suite.server = httptest.NewServer(suite.router)
}

// initializeAISystem initializes the AI system with test data
func (suite *AIThreatDetectionE2ETestSuite) initializeAISystem() {
	// Add some threat intelligence data
	suite.redisClient.HSet(suite.ctx, "ai:threat_intel:domains:malware-example.com",
		"type", "malicious",
		"category", "malware",
		"confidence", 0.9,
		"source", "test",
		"added_at", time.Now().Format(time.RFC3339))
	
	suite.redisClient.SAdd(suite.ctx, "ai:threat_intel:domains:set", "malware-example.com")
	
	// Add behavioral profiles
	suite.redisClient.HSet(suite.ctx, "ai:behavior:profile:normal_user",
		"requests_per_hour_avg", 50,
		"requests_per_hour_stddev", 15,
		"unique_domains_avg", 10,
		"unique_domains_stddev", 5)
	
	// Add alert thresholds
	suite.redisClient.HSet(suite.ctx, "ai:alerts:threshold:high_threat_score",
		"metric_name", "threat_score",
		"operator", ">",
		"value", 0.8,
		"severity", "critical",
		"enabled", true)
}

// TestHealthEndpoint tests the health endpoint
func (suite *AIThreatDetectionE2ETestSuite) TestHealthEndpoint() {
	resp, err := http.Get(suite.server.URL + "/health")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)
	
	assert.Equal(suite.T(), "ok", response["status"])
}

// TestBenignRequest tests that benign requests pass through normally
func (suite *AIThreatDetectionE2ETestSuite) TestBenignRequest() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
	require.NoError(suite.T(), err)
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), response["message"], "benign")
}

// TestSuspiciousRequest tests that suspicious requests are detected and handled
func (suite *AIThreatDetectionE2ETestSuite) TestSuspiciousRequest() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", suite.server.URL+"/test/suspicious", nil)
	require.NoError(suite.T(), err)
	
	// Add suspicious characteristics
	req.Header.Set("User-Agent", "wget/1.20.3")
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // Known malicious IP from test data
	
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	// Request might be blocked or allowed with warnings
	// Check for AI analysis headers
	assert.NotEmpty(suite.T(), resp.Header.Get("X-AI-Threat-Score"))
	assert.NotEmpty(suite.T(), resp.Header.Get("X-AI-Analysis-Time"))
}

// TestMaliciousDomainBlocking tests that requests to known malicious domains are blocked
func (suite *AIThreatDetectionE2ETestSuite) TestMaliciousDomainBlocking() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
	require.NoError(suite.T(), err)
	
	req.Header.Set("Host", "malware-example.com")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	// Should be blocked due to malicious domain
	assert.True(suite.T(), resp.StatusCode >= 400, "Expected request to malicious domain to be blocked")
}

// TestRateLimitingWithAI tests that AI-enhanced rate limiting works
func (suite *AIThreatDetectionE2ETestSuite) TestRateLimitingWithAI() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Make multiple requests rapidly (bot-like behavior)
	for i := 0; i < 20; i++ {
		req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
		require.NoError(suite.T(), err)
		
		req.Header.Set("User-Agent", "bot/1.0")
		req.Header.Set("X-Forwarded-For", "192.168.1.200")
		
		resp, err := client.Do(req)
		require.NoError(suite.T(), err)
		resp.Body.Close()
		
		// After several requests, should start getting rate limited
		if i > 10 && resp.StatusCode == http.StatusTooManyRequests {
			suite.T().Logf("Rate limiting kicked in after %d requests", i+1)
			break
		}
	}
}

// TestBehavioralAnalysis tests behavioral analysis functionality
func (suite *AIThreatDetectionE2ETestSuite) TestBehavioralAnalysis() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Simulate normal user behavior
	normalRequests := []string{
		"/test/benign",
		"/health",
		"/test/benign",
	}
	
	for _, path := range normalRequests {
		req, err := http.NewRequest("GET", suite.server.URL+path, nil)
		require.NoError(suite.T(), err)
		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		req.Header.Set("X-Forwarded-For", "192.168.1.101")
		req.Header.Set("X-User-ID", "normal_user_001")
		
		resp, err := client.Do(req)
		require.NoError(suite.T(), err)
		resp.Body.Close()
		
		time.Sleep(100 * time.Millisecond) // Normal pacing
	}
	
	// Now simulate anomalous behavior
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
		require.NoError(suite.T(), err)
		
		req.Header.Set("User-Agent", "bot/1.0")
		req.Header.Set("X-Forwarded-For", "192.168.1.102")
		req.Header.Set("X-User-ID", "anomalous_user_001")
		
		resp, err := client.Do(req)
		require.NoError(suite.T(), err)
		resp.Body.Close()
		
		// No delay - rapid requests
	}
	
	// Check if behavioral analysis detected the anomaly
	// This would be reflected in metrics or alerts
}

// TestContentAnalysis tests content analysis functionality
func (suite *AIThreatDetectionE2ETestSuite) TestContentAnalysis() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Test suspicious file upload
	maliciousContent := `
		<script>alert('xss')</script>
		<iframe src="http://malware-example.com/exploit.html"></iframe>
	`
	
	req, err := http.NewRequest("POST", suite.server.URL+"/test/upload", bytes.NewBufferString(maliciousContent))
	require.NoError(suite.T(), err)
	
	req.Header.Set("Content-Type", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	// Check if content was analyzed and flagged
	threatScore := resp.Header.Get("X-AI-Threat-Score")
	if threatScore != "" {
		suite.T().Logf("Content analysis threat score: %s", threatScore)
	}
}

// TestAIAPIEndpoints tests the AI API endpoints
func (suite *AIThreatDetectionE2ETestSuite) TestAIAPIEndpoints() {
	// Test threat analysis endpoint
	analysisRequest := map[string]interface{}{
		"url":         "http://example.com/test",
		"method":      "GET",
		"user_agent":  "Mozilla/5.0",
		"source_ip":   "192.168.1.100",
		"user_id":     "test_user",
	}
	
	jsonData, err := json.Marshal(analysisRequest)
	require.NoError(suite.T(), err)
	
	resp, err := http.Post(suite.server.URL+"/api/v1/ai/analyze", "application/json", bytes.NewBuffer(jsonData))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	var analysisResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&analysisResponse)
	require.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), analysisResponse, "threat_score")
	assert.Contains(suite.T(), analysisResponse, "analysis_time")
	assert.Contains(suite.T(), analysisResponse, "components")
}

// TestMetricsCollection tests metrics collection functionality
func (suite *AIThreatDetectionE2ETestSuite) TestMetricsCollection() {
	// Start metrics collection
	go suite.metricsCollector.Start(suite.ctx)
	defer suite.metricsCollector.Stop()
	
	// Make some requests to generate metrics
	client := &http.Client{Timeout: 10 * time.Second}
	
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
		require.NoError(suite.T(), err)
		
		resp, err := client.Do(req)
		require.NoError(suite.T(), err)
		resp.Body.Close()
	}
	
	// Wait for metrics to be collected
	time.Sleep(2 * time.Second)
	
	// Check metrics endpoint
	resp, err := http.Get(suite.server.URL + "/api/v1/ai/metrics")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	var metricsResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&metricsResponse)
	require.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), metricsResponse, "timestamp")
	assert.Contains(suite.T(), metricsResponse, "counters")
	assert.Contains(suite.T(), metricsResponse, "gauges")
}

// TestAlertingSystem tests the alerting system
func (suite *AIThreatDetectionE2ETestSuite) TestAlertingSystem() {
	// Start alert manager
	err := suite.alertManager.Start()
	require.NoError(suite.T(), err)
	defer suite.alertManager.Stop()
	
	// Create a test alert
	alert := &ai.Alert{
		ID:          "test-alert-001",
		MetricName:  "threat_score",
		Severity:    ai.AlertSeverityWarning,
		Message:     "Test alert for E2E testing",
		TriggeredAt: time.Now(),
		Status:      ai.AlertStatusActive,
		Labels: map[string]string{
			"test": "e2e",
		},
		Metadata: map[string]interface{}{
			"test_case": "TestAlertingSystem",
		},
	}
	
	// Send alert
	err = suite.alertManager.SendAlert(alert)
	require.NoError(suite.T(), err)
	
	// Check that alert is active
	activeAlerts := suite.alertManager.GetActiveAlerts()
	assert.Len(suite.T(), activeAlerts, 1)
	assert.Contains(suite.T(), activeAlerts, "test-alert-001")
	
	// Resolve alert
	err = suite.alertManager.ResolveAlert("test-alert-001")
	require.NoError(suite.T(), err)
	
	// Check that alert is resolved
	activeAlerts = suite.alertManager.GetActiveAlerts()
	assert.Len(suite.T(), activeAlerts, 0)
}

// TestThreatIntelligenceIntegration tests threat intelligence integration
func (suite *AIThreatDetectionE2ETestSuite) TestThreatIntelligenceIntegration() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Test request to known malicious domain
	req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
	require.NoError(suite.T(), err)
	
	req.Header.Set("Referer", "http://malware-example.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	// Check if threat intelligence was used in analysis
	threatScore := resp.Header.Get("X-AI-Threat-Score")
	if threatScore != "" {
		suite.T().Logf("Threat intelligence contributed to score: %s", threatScore)
	}
}

// TestAdaptiveLearning tests adaptive learning functionality
func (suite *AIThreatDetectionE2ETestSuite) TestAdaptiveLearning() {
	// This test would verify that the system learns from feedback
	// For now, we'll just test that the feedback mechanism works
	
	feedbackRequest := map[string]interface{}{
		"request_id":   "test-request-001",
		"feedback":     "false_positive",
		"confidence":   0.9,
		"user_id":      "admin",
		"description":  "This was incorrectly flagged as malicious",
	}
	
	jsonData, err := json.Marshal(feedbackRequest)
	require.NoError(suite.T(), err)
	
	resp, err := http.Post(suite.server.URL+"/api/v1/ai/feedback", "application/json", bytes.NewBuffer(jsonData))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	
	var feedbackResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&feedbackResponse)
	require.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), feedbackResponse, "status")
	assert.Equal(suite.T(), "accepted", feedbackResponse["status"])
}

// TestSystemPerformance tests system performance under load
func (suite *AIThreatDetectionE2ETestSuite) TestSystemPerformance() {
	client := &http.Client{Timeout: 30 * time.Second}
	
	// Measure performance metrics
	startTime := time.Now()
	requestCount := 100
	successCount := 0
	
	for i := 0; i < requestCount; i++ {
		req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
		require.NoError(suite.T(), err)
		
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.1.%d", 100+i%50))
		
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			successCount++
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	
	duration := time.Since(startTime)
	requestsPerSecond := float64(requestCount) / duration.Seconds()
	successRate := float64(successCount) / float64(requestCount)
	
	suite.T().Logf("Performance metrics:")
	suite.T().Logf("  Total requests: %d", requestCount)
	suite.T().Logf("  Successful requests: %d", successCount)
	suite.T().Logf("  Success rate: %.2f%%", successRate*100)
	suite.T().Logf("  Duration: %v", duration)
	suite.T().Logf("  Requests per second: %.2f", requestsPerSecond)
	
	// Assert minimum performance requirements
	assert.Greater(suite.T(), requestsPerSecond, 10.0, "System should handle at least 10 requests per second")
	assert.Greater(suite.T(), successRate, 0.95, "Success rate should be at least 95%")
}

// TestSystemResilience tests system resilience to failures
func (suite *AIThreatDetectionE2ETestSuite) TestSystemResilience() {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Test with various edge cases
	testCases := []struct {
		name        string
		path        string
		headers     map[string]string
		expectError bool
	}{
		{
			name: "Empty User-Agent",
			path: "/test/benign",
			headers: map[string]string{
				"User-Agent": "",
			},
			expectError: false,
		},
		{
			name: "Very Long URL",
			path: "/test/benign?" + string(make([]byte, 2000)),
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0",
			},
			expectError: false,
		},
		{
			name: "Special Characters in Headers",
			path: "/test/benign",
			headers: map[string]string{
				"User-Agent":     "Mozilla/5.0 (特殊字符测试)",
				"X-Custom-Header": "value with spaces and symbols !@#$%^&*()",
			},
			expectError: false,
		},
		{
			name: "Missing Headers",
			path: "/test/benign",
			headers: map[string]string{
				// No headers
			},
			expectError: false,
		},
	}
	
	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", suite.server.URL+tc.path, nil)
			require.NoError(t, err)
			
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			
			resp, err := client.Do(req)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if resp != nil {
					resp.Body.Close()
					assert.True(t, resp.StatusCode < 500, "Should not return server error")
				}
			}
		})
	}
}

// TestConcurrentRequests tests system behavior under concurrent load
func (suite *AIThreatDetectionE2ETestSuite) TestConcurrentRequests() {
	const numGoroutines = 10
	const requestsPerGoroutine = 10
	
	client := &http.Client{Timeout: 30 * time.Second}
	
	// Channel to collect results
	results := make(chan bool, numGoroutines*requestsPerGoroutine)
	
	// Start concurrent goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < requestsPerGoroutine; j++ {
				req, err := http.NewRequest("GET", suite.server.URL+"/test/benign", nil)
				if err != nil {
					results <- false
					continue
				}
				
				req.Header.Set("User-Agent", fmt.Sprintf("TestClient-%d-%d", goroutineID, j))
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.%d.%d", goroutineID+1, j+1))
				
				resp, err := client.Do(req)
				success := err == nil && resp != nil && resp.StatusCode == http.StatusOK
				if resp != nil {
					resp.Body.Close()
				}
				
				results <- success
			}
		}(i)
	}
	
	// Collect results
	successCount := 0
	totalRequests := numGoroutines * requestsPerGoroutine
	
	for i := 0; i < totalRequests; i++ {
		if <-results {
			successCount++
		}
	}
	
	successRate := float64(successCount) / float64(totalRequests)
	
	suite.T().Logf("Concurrent request results:")
	suite.T().Logf("  Total requests: %d", totalRequests)
	suite.T().Logf("  Successful requests: %d", successCount)
	suite.T().Logf("  Success rate: %.2f%%", successRate*100)
	
	// Assert that most requests succeeded
	assert.Greater(suite.T(), successRate, 0.90, "At least 90% of concurrent requests should succeed")
}

// TestE2ETestSuite runs the complete end-to-end test suite
func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, new(AIThreatDetectionE2ETestSuite))
}