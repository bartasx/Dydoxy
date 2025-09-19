package ai

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestHealthMonitor() *HealthMonitor {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	adaptiveLearning := NewAdaptiveLearningSystem(&MockAIStorage{}, threatDetector, &MockModelManager{}, logger)
	adaptiveRateLimiter := NewAIAdaptiveRateLimiter(threatDetector, &MockMultiLayerRateLimiter{}, nil, nil, logger)
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	storage := &MockAIStorage{}
	auditLogger := NewAuditLogger(logger, storage)
	
	monitor := NewHealthMonitor(
		threatDetector,
		adaptiveLearning,
		adaptiveRateLimiter,
		middleware,
		storage,
		auditLogger,
		logger,
	)
	
	return monitor
}

func TestHealthMonitor_Creation(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	assert.NotNil(t, monitor)
	assert.NotNil(t, monitor.config)
	assert.NotNil(t, monitor.metrics)
	assert.NotNil(t, monitor.checks)
	assert.NotNil(t, monitor.alerts)
	assert.True(t, monitor.config.Enabled)
	
	// Check that health checks were initialized
	assert.Contains(t, monitor.checks, "threat_detector")
	assert.Contains(t, monitor.checks, "adaptive_learning")
	assert.Contains(t, monitor.checks, "adaptive_rate_limiter")
	assert.Contains(t, monitor.checks, "middleware")
	assert.Contains(t, monitor.checks, "storage")
	assert.Contains(t, monitor.checks, "audit_logger")
}

func TestHealthMonitor_GetHealth(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Perform a health check first
	ctx := context.Background()
	monitor.performHealthCheck(ctx)
	
	health, err := monitor.GetHealth(ctx)
	require.NoError(t, err)
	
	assert.NotNil(t, health)
	assert.NotEqual(t, HealthStatusUnknown, health.OverallHealth)
	assert.NotEmpty(t, health.ComponentHealth)
	assert.GreaterOrEqual(t, health.HealthScore, 0.0)
	assert.LessOrEqual(t, health.HealthScore, 100.0)
	assert.Greater(t, health.Uptime, time.Duration(0))
	
	// Check that all expected components are present
	expectedComponents := []string{
		"threat_detector", "adaptive_learning", "adaptive_rate_limiter",
		"middleware", "storage", "audit_logger",
	}
	
	for _, component := range expectedComponents {
		assert.Contains(t, health.ComponentHealth, component)
		componentHealth := health.ComponentHealth[component]
		assert.NotEmpty(t, componentHealth.Name)
		assert.NotEqual(t, HealthStatusUnknown, componentHealth.Status)
		assert.False(t, componentHealth.LastCheck.IsZero())
	}
}

func TestHealthMonitor_PerformHealthCheck(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Mock threat detector for health check
	threatDetector := monitor.threatDetector.(*MockAIThreatDetector)
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(
		&ThreatAnalysisResult{
			RequestID:   "health-check",
			IsThreat:    false,
			Confidence:  0.1,
			Timestamp:   time.Now(),
		}, nil)
	threatDetector.On("GetStats", mock.Anything).Return(
		&AIThreatStats{
			TotalRequests:   1000,
			ThreatsDetected: 50,
			ModelAccuracy:   map[string]float64{"content_model": 0.95},
		}, nil)
	threatDetector.On("GetHealth", mock.Anything).Return(
		&AIHealthStatus{
			Overall: "healthy",
		}, nil)
	
	// Mock storage for health check
	storage := monitor.storage.(*MockAIStorage)
	storage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil)
	storage.On("LoadTrainingExamples", mock.Anything, 1, 0).Return([]*TrainingExample{}, nil)
	storage.On("DeleteTrainingExample", mock.Anything, "health-check").Return(nil)
	storage.On("LoadThreatPolicies", mock.Anything).Return(&ThreatPolicies{}, nil)
	
	ctx := context.Background()
	monitor.performHealthCheck(ctx)
	
	// Check that metrics were updated
	assert.False(t, monitor.metrics.LastHealthCheck.IsZero())
	assert.NotEmpty(t, monitor.metrics.ComponentHealth)
	assert.GreaterOrEqual(t, monitor.metrics.HealthScore, 0.0)
	assert.NotEqual(t, HealthStatusUnknown, monitor.metrics.OverallHealth)
	
	threatDetector.AssertExpectations(t)
	storage.AssertExpectations(t)
}

func TestHealthMonitor_HealthScoreCalculation(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Set up component health with different statuses
	monitor.metrics.ComponentHealth = map[string]*ComponentHealth{
		"component1": {
			Status: HealthStatusHealthy,
			Weight: 2.0,
		},
		"component2": {
			Status: HealthStatusDegraded,
			Weight: 1.0,
		},
		"component3": {
			Status: HealthStatusCritical,
			Weight: 1.0,
		},
	}
	
	score := monitor.calculateOverallHealthScore()
	
	// Expected calculation: ((4.0 * 2.0) + (3.0 * 1.0) + (1.0 * 1.0)) / (2.0 + 1.0 + 1.0) * 25
	// = (8.0 + 3.0 + 1.0) / 4.0 * 25 = 3.0 * 25 = 75.0
	assert.Equal(t, 75.0, score)
}

func TestHealthMonitor_OverallHealthStatusDetermination(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	tests := []struct {
		score          float64
		expectedStatus HealthStatus
	}{
		{95.0, HealthStatusHealthy},
		{85.0, HealthStatusDegraded},
		{60.0, HealthStatusUnhealthy},
		{30.0, HealthStatusCritical},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.expectedStatus), func(t *testing.T) {
			monitor.metrics.HealthScore = tt.score
			status := monitor.determineOverallHealthStatus()
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestHealthMonitor_PrometheusMetrics(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Set up some test metrics
	monitor.metrics.HealthScore = 85.5
	monitor.metrics.ComponentHealth = map[string]*ComponentHealth{
		"test_component": {
			Status:       HealthStatusHealthy,
			ResponseTime: 100 * time.Millisecond,
			ErrorRate:    0.02,
			Availability: 0.99,
		},
	}
	monitor.metrics.PerformanceMetrics = &PerformanceMetrics{
		AverageResponseTime: 150 * time.Millisecond,
		P95ResponseTime:     300 * time.Millisecond,
		P99ResponseTime:     500 * time.Millisecond,
		CacheHitRate:        0.85,
	}
	monitor.metrics.ErrorMetrics = &ErrorMetrics{
		TotalErrors:    100,
		ErrorRate:      0.05,
		CriticalErrors: 5,
	}
	monitor.metrics.ThroughputMetrics = &ThroughputMetrics{
		RequestsPerSecond:  50.0,
		ConcurrentRequests: 25,
		QueueLength:        10,
	}
	monitor.metrics.SystemMetrics = &SystemMetrics{
		CPUUsage:    60.0,
		MemoryUsage: 70.0,
		Goroutines:  150,
		HeapSize:    1024 * 1024 * 200,
	}
	monitor.metrics.Uptime = 2 * time.Hour
	
	prometheusMetrics := monitor.GetPrometheusMetrics()
	
	assert.NotEmpty(t, prometheusMetrics)
	assert.Contains(t, prometheusMetrics, "ai_system_health_score 85.50")
	assert.Contains(t, prometheusMetrics, "ai_component_health{component=\"test_component\"} 4")
	assert.Contains(t, prometheusMetrics, "ai_component_response_time{component=\"test_component\"} 0.100")
	assert.Contains(t, prometheusMetrics, "ai_component_error_rate{component=\"test_component\"} 0.0200")
	assert.Contains(t, prometheusMetrics, "ai_component_availability{component=\"test_component\"} 0.9900")
	assert.Contains(t, prometheusMetrics, "ai_average_response_time 0.150")
	assert.Contains(t, prometheusMetrics, "ai_cache_hit_rate 0.8500")
	assert.Contains(t, prometheusMetrics, "ai_total_errors 100")
	assert.Contains(t, prometheusMetrics, "ai_requests_per_second 50.00")
	assert.Contains(t, prometheusMetrics, "ai_cpu_usage 60.00")
	assert.Contains(t, prometheusMetrics, "ai_uptime_seconds 7200")
}

func TestHealthMonitor_AlertGeneration(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Create a component with high error rate
	componentHealth := &ComponentHealth{
		Name:      "test_component",
		Status:    HealthStatusDegraded,
		ErrorRate: 0.1, // 10% error rate
	}
	
	// Set alert threshold
	monitor.config.AlertThresholds["error_rate"] = 0.05 // 5% threshold
	
	monitor.checkForIssues("test_component", componentHealth)
	
	// Check that alert was generated
	alerts := monitor.alerts.GetAlerts(10)
	assert.NotEmpty(t, alerts)
	
	found := false
	for _, alert := range alerts {
		if alert.Type == AlertTypeHighErrorRate && alert.Component == "test_component" {
			found = true
			assert.Equal(t, AlertSeverityWarning, alert.Severity)
			assert.Contains(t, alert.Description, "error rate")
			break
		}
	}
	assert.True(t, found, "Expected high error rate alert not found")
}

func TestHealthMonitor_Configuration(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Test default configuration
	config := monitor.GetConfig()
	assert.True(t, config.Enabled)
	assert.Equal(t, 30*time.Second, config.CheckInterval)
	assert.Equal(t, 10*time.Second, config.HealthCheckTimeout)
	assert.NotEmpty(t, config.AlertThresholds)
	assert.NotEmpty(t, config.ComponentWeights)
	
	// Test configuration update
	newConfig := &HealthConfig{
		Enabled:                false,
		CheckInterval:          60 * time.Second,
		HealthCheckTimeout:     5 * time.Second,
		EnablePrometheusExport: false,
		DegradedThreshold:      80.0,
		UnhealthyThreshold:     60.0,
		AlertThresholds: map[string]float64{
			"error_rate": 0.1,
		},
	}
	
	monitor.SetConfig(newConfig)
	updatedConfig := monitor.GetConfig()
	
	assert.False(t, updatedConfig.Enabled)
	assert.Equal(t, 60*time.Second, updatedConfig.CheckInterval)
	assert.Equal(t, 5*time.Second, updatedConfig.HealthCheckTimeout)
	assert.False(t, updatedConfig.EnablePrometheusExport)
	assert.Equal(t, 80.0, updatedConfig.DegradedThreshold)
	assert.Equal(t, 60.0, updatedConfig.UnhealthyThreshold)
	assert.Equal(t, 0.1, updatedConfig.AlertThresholds["error_rate"])
}

func TestHealthMonitor_HealthStatusToFloat(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	tests := []struct {
		status   HealthStatus
		expected float64
	}{
		{HealthStatusHealthy, 4.0},
		{HealthStatusDegraded, 3.0},
		{HealthStatusUnhealthy, 2.0},
		{HealthStatusCritical, 1.0},
		{HealthStatusUnknown, 0.0},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := monitor.healthStatusToFloat(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestThreatDetectorHealthCheck(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	healthCheck := &ThreatDetectorHealthCheck{
		detector: threatDetector,
		logger:   logger,
	}
	
	// Mock successful threat analysis
	threatDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(
		&ThreatAnalysisResult{
			RequestID:   "health-check",
			IsThreat:    false,
			Confidence:  0.1,
			Timestamp:   time.Now(),
		}, nil)
	
	threatDetector.On("GetStats", mock.Anything).Return(
		&AIThreatStats{
			TotalRequests:   1000,
			ThreatsDetected: 50,
			ModelAccuracy:   map[string]float64{"content_model": 0.95},
		}, nil)
	
	threatDetector.On("GetHealth", mock.Anything).Return(
		&AIHealthStatus{
			Overall: "healthy",
		}, nil)
	
	health := healthCheck.Check(context.Background())
	
	assert.Equal(t, "threat_detector", health.Name)
	assert.Equal(t, HealthStatusHealthy, health.Status)
	assert.Equal(t, 0.0, health.ErrorRate)
	assert.Equal(t, 1.0, health.Availability)
	assert.Contains(t, health.Details, "total_requests")
	assert.Contains(t, health.Details, "threats_detected")
	assert.Contains(t, health.Metrics, "threat_detection_rate")
	assert.Equal(t, 3.0, healthCheck.Weight())
	assert.Contains(t, healthCheck.Dependencies(), "storage")
	
	threatDetector.AssertExpectations(t)
}

func TestStorageHealthCheck(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	healthCheck := &StorageHealthCheck{
		storage: storage,
		logger:  logger,
	}
	
	// Mock successful storage operations
	storage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil)
	storage.On("LoadTrainingExamples", mock.Anything, 1, 0).Return([]*TrainingExample{}, nil)
	storage.On("DeleteTrainingExample", mock.Anything, "health-check").Return(nil)
	storage.On("LoadThreatPolicies", mock.Anything).Return(&ThreatPolicies{}, nil)
	
	health := healthCheck.Check(context.Background())
	
	assert.Equal(t, "storage", health.Name)
	assert.Equal(t, HealthStatusHealthy, health.Status)
	assert.Equal(t, 0.0, health.ErrorRate)
	assert.Equal(t, 1.0, health.Availability)
	assert.Contains(t, health.Details, "response_time_ms")
	assert.Contains(t, health.Metrics, "response_time")
	assert.Equal(t, 2.5, healthCheck.Weight())
	assert.Empty(t, healthCheck.Dependencies())
	
	storage.AssertExpectations(t)
}

func TestAlertManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	alertManager := NewAlertManager(logger)
	
	assert.NotNil(t, alertManager)
	assert.NotNil(t, alertManager.config)
	assert.True(t, alertManager.config.Enabled)
	
	// Test sending an alert
	alert := &Alert{
		ID:          "test-alert-1",
		Type:        AlertTypeHighErrorRate,
		Severity:    AlertSeverityWarning,
		Component:   "test_component",
		Title:       "Test Alert",
		Description: "This is a test alert",
		Timestamp:   time.Now(),
	}
	
	alertManager.SendAlert(context.Background(), alert)
	
	// Check that alert was added to history
	alerts := alertManager.GetAlerts(10)
	assert.Len(t, alerts, 1)
	assert.Equal(t, "test-alert-1", alerts[0].ID)
	assert.Equal(t, AlertTypeHighErrorRate, alerts[0].Type)
	assert.Equal(t, "Test Alert", alerts[0].Title)
}

func TestHealthMonitor_Start_Disabled(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Disable health monitoring
	config := monitor.GetConfig()
	config.Enabled = false
	monitor.SetConfig(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	// This should return immediately since monitoring is disabled
	monitor.Start(ctx)
	
	// No assertions needed - just ensuring it doesn't hang
}

func TestHealthMonitor_JoinStrings(t *testing.T) {
	tests := []struct {
		strs     []string
		sep      string
		expected string
	}{
		{[]string{}, ",", ""},
		{[]string{"a"}, ",", "a"},
		{[]string{"a", "b"}, ",", "a,b"},
		{[]string{"a", "b", "c"}, ", ", "a, b, c"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := joinStrings(tt.strs, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHealthMonitor_ComponentHealthIssues(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Test component with critical status
	componentHealth := &ComponentHealth{
		Name:   "critical_component",
		Status: HealthStatusCritical,
	}
	
	monitor.checkForIssues("critical_component", componentHealth)
	
	alerts := monitor.alerts.GetAlerts(10)
	assert.NotEmpty(t, alerts)
	
	found := false
	for _, alert := range alerts {
		if alert.Type == AlertTypeComponentDown && alert.Component == "critical_component" {
			found = true
			assert.Equal(t, AlertSeverityCritical, alert.Severity)
			break
		}
	}
	assert.True(t, found, "Expected component down alert not found")
}

func TestHealthMonitor_ResponseTimeAlert(t *testing.T) {
	monitor := setupTestHealthMonitor()
	
	// Create a component with high response time
	componentHealth := &ComponentHealth{
		Name:         "slow_component",
		Status:       HealthStatusHealthy,
		ResponseTime: 2 * time.Second,
	}
	
	// Set response time threshold
	monitor.config.AlertThresholds["response_time"] = 1.0 // 1 second threshold
	
	monitor.checkForIssues("slow_component", componentHealth)
	
	// Check that alert was generated
	alerts := monitor.alerts.GetAlerts(10)
	assert.NotEmpty(t, alerts)
	
	found := false
	for _, alert := range alerts {
		if alert.Type == AlertTypeHighLatency && alert.Component == "slow_component" {
			found = true
			assert.Equal(t, AlertSeverityWarning, alert.Severity)
			assert.Contains(t, alert.Description, "response time")
			break
		}
	}
	assert.True(t, found, "Expected high latency alert not found")
}