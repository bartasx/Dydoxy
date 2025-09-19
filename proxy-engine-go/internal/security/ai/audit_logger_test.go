package ai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"../../ratelimit"
)

// Mock AuditStorage for testing
type MockAuditStorage struct {
	mock.Mock
}

func (m *MockAuditStorage) SaveAuditEvent(ctx context.Context, event *AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockAuditStorage) LoadAuditEvents(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditEvent, error) {
	args := m.Called(ctx, filter, limit, offset)
	return args.Get(0).([]*AuditEvent), args.Error(1)
}

func (m *MockAuditStorage) DeleteAuditEvents(ctx context.Context, filter *AuditFilter) (int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditStorage) GetAuditStats(ctx context.Context, timeRange TimeRange) (*AuditStorageStats, error) {
	args := m.Called(ctx, timeRange)
	return args.Get(0).(*AuditStorageStats), args.Error(1)
}

func (m *MockAuditStorage) ArchiveAuditEvents(ctx context.Context, beforeTime time.Time) (int64, error) {
	args := m.Called(ctx, beforeTime)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditStorage) CleanupExpiredEvents(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func setupTestAuditLogger() (*AuditLogger, *MockAuditStorage) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAuditStorage{}
	auditLogger := NewAuditLogger(logger, storage)
	
	return auditLogger, storage
}

func TestAuditLogger_Creation(t *testing.T) {
	logger := logrus.New()
	storage := &MockAuditStorage{}
	
	auditLogger := NewAuditLogger(logger, storage)
	
	assert.NotNil(t, auditLogger)
	assert.NotNil(t, auditLogger.config)
	assert.NotNil(t, auditLogger.stats)
	assert.NotNil(t, auditLogger.retentionPolicy)
	assert.True(t, auditLogger.config.Enabled)
	assert.Empty(t, auditLogger.eventBuffer)
}

func TestAuditLogger_LogThreatDetection(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	request := &ThreatAnalysisRequest{
		RequestID: "test-req-123",
		UserID:    "user123",
		SessionID: "session456",
		ClientIP:  "192.168.1.1",
		UserAgent: "test-agent",
		URL:       "https://example.com/test",
		Method:    "GET",
		Headers:   map[string]string{"Content-Type": "application/json"},
		Body:      []byte("test body"),
	}
	
	result := &ThreatAnalysisResult{
		RequestID:     "test-req-123",
		IsThreat:      true,
		ThreatType:    ThreatTypeMalware,
		ThreatLevel:   ThreatLevelHigh,
		Confidence:    0.9,
		Reasons:       []string{"Malicious payload detected"},
		MLPredictions: map[string]float64{"malware": 0.9},
		Timestamp:     time.Now(),
	}
	
	responseTime := 100 * time.Millisecond
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogThreatDetection(context.Background(), request, result, responseTime)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventThreatDetection])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityError])
	assert.Equal(t, int64(1), stats.EventsByAction[AuditActionAnalyze])
	assert.Equal(t, int64(1), stats.EventsBySource["ai_threat_detector"])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogBehaviorAnalysis(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	analysis := &BehaviorAnalysis{
		Subject:         "user:123",
		IsAnomalous:     true,
		AnomalyScore:    0.8,
		AnomalyReasons:  []string{"Unusual request frequency"},
		ProfileData:     map[string]interface{}{"avg_requests": 10.5},
		Timestamp:       time.Now(),
	}
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogBehaviorAnalysis(context.Background(), "user:123", analysis)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventBehaviorAnalysis])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityCritical]) // 0.8 score = critical
	assert.Equal(t, int64(1), stats.EventsBySource["behavioral_analyzer"])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogRateLimit(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	request := &AdaptiveRateLimitRequest{
		RateLimitRequest: &ratelimit.RateLimitRequest{
			UserID: "user123",
			IP:     "192.168.1.1",
		},
	}
	
	result := &AdaptiveRateLimitResult{
		MultiLayerResult: &ratelimit.MultiLayerResult{
			Allowed:  false,
			DeniedBy: "threat_based",
		},
		AppliedMultiplier:   2.0,
		AdjustmentReason:    "threat_level_high",
		EmergencyMode:       false,
	}
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogRateLimit(context.Background(), request, result)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventRateLimit])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityWarning]) // Blocked = warning
	assert.Equal(t, int64(1), stats.EventsByAction[AuditActionRateLimit])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogModelUpdate(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	modelName := "content_analysis"
	version := "1.2.0"
	trainingSize := 5000
	metrics := map[string]float64{
		"accuracy":  0.95,
		"precision": 0.93,
		"recall":    0.97,
		"f1_score":  0.95,
	}
	duration := 30 * time.Minute
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogModelUpdate(context.Background(), modelName, version, trainingSize, metrics, duration)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventModelUpdate])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityInfo])
	assert.Equal(t, int64(1), stats.EventsByAction[AuditActionUpdate])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogConfigChange(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	component := "threat_detector"
	userID := "admin123"
	changes := map[string]interface{}{
		"confidence_threshold": map[string]interface{}{
			"old": 0.7,
			"new": 0.8,
		},
		"enabled": map[string]interface{}{
			"old": true,
			"new": false,
		},
	}
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogConfigChange(context.Background(), component, userID, changes)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventConfigChange])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityWarning])
	assert.Equal(t, int64(1), stats.EventsByAction[AuditActionConfigChange])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogSecurityIncident(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	incidentType := "brute_force_attack"
	description := "Multiple failed login attempts detected"
	severity := AuditSeverityCritical
	context := map[string]interface{}{
		"failed_attempts": 10,
		"source_ip":       "192.168.1.100",
		"target_user":     "admin",
	}
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogSecurityIncident(context.Background(), incidentType, description, severity, context)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventSecurityIncident])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityCritical])
	assert.Equal(t, int64(1), stats.EventsByAction[AuditActionBlock])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogError(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	component := "model_manager"
	errorType := "training_error"
	errorMessage := "Failed to load training data"
	err := fmt.Errorf("file not found: training.csv")
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogError(context.Background(), component, errorType, errorMessage, err)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventError])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityError])
	assert.Equal(t, int64(1), stats.EventsBySource["error_handler"])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_LogUserAction(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	userID := "user123"
	action := "login"
	resource := "admin_panel"
	success := true
	clientIP := "192.168.1.1"
	
	// Mock storage call
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil)
	
	auditLogger.LogUserAction(context.Background(), userID, action, resource, success, clientIP)
	
	// Check statistics
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(1), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventUserAction])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityInfo]) // Success = info
	assert.Equal(t, int64(1), stats.EventsByAction[AuditAction(action)])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_Disabled(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	// Disable audit logging
	config := auditLogger.GetConfig()
	config.Enabled = false
	auditLogger.SetConfig(config)
	
	request := &ThreatAnalysisRequest{RequestID: "test"}
	result := &ThreatAnalysisResult{RequestID: "test", IsThreat: false}
	
	auditLogger.LogThreatDetection(context.Background(), request, result, time.Millisecond)
	
	// Should not have logged anything
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(0), stats.TotalEvents)
	
	// Storage should not have been called
	storage.AssertNotCalled(t, "SaveAuditEvent")
}

func TestAuditLogger_BufferFlushing(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	// Set small buffer size for testing
	config := auditLogger.GetConfig()
	config.BufferSize = 2
	auditLogger.SetConfig(config)
	
	// Mock storage calls
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil).Times(3)
	
	// Log events to fill buffer
	for i := 0; i < 3; i++ {
		auditLogger.LogUserAction(context.Background(), "user123", "test", "resource", true, "127.0.0.1")
	}
	
	// Wait for async flush
	time.Sleep(100 * time.Millisecond)
	
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(3), stats.TotalEvents)
	assert.Greater(t, stats.EventsFlushed, int64(0))
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_SensitiveDataMasking(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	// Enable sensitive data masking
	config := auditLogger.GetConfig()
	config.MaskSensitiveFields = true
	auditLogger.SetConfig(config)
	
	event := &AuditEvent{
		UserAgent: "Mozilla/5.0 (sensitive-info)",
		ThreatAnalysis: &ThreatAnalysisResult{
			Body: []byte("sensitive request body"),
		},
		Metadata: map[string]interface{}{
			"password": "secret123",
			"token":    "bearer-token-xyz",
			"normal":   "normal-value",
		},
	}
	
	auditLogger.maskSensitiveData(event)
	
	// Check that sensitive data was masked
	assert.Contains(t, event.UserAgent, "***")
	assert.Equal(t, []byte("***MASKED***"), event.ThreatAnalysis.Body)
	assert.Contains(t, event.Metadata["password"].(string), "***")
	assert.Contains(t, event.Metadata["token"].(string), "***")
	assert.Equal(t, "normal-value", event.Metadata["normal"]) // Should not be masked
}

func TestAuditLogger_ThreatLevelMapping(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	tests := []struct {
		threatLevel     ThreatLevel
		expectedSeverity AuditSeverity
	}{
		{ThreatLevelCritical, AuditSeverityCritical},
		{ThreatLevelHigh, AuditSeverityError},
		{ThreatLevelMedium, AuditSeverityWarning},
		{ThreatLevelLow, AuditSeverityInfo},
		{ThreatLevelNone, AuditSeverityInfo},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.threatLevel), func(t *testing.T) {
			severity := auditLogger.mapThreatLevelToSeverity(tt.threatLevel)
			assert.Equal(t, tt.expectedSeverity, severity)
		})
	}
}

func TestAuditLogger_TagGeneration(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	tests := []struct {
		name     string
		result   *ThreatAnalysisResult
		expected []string
	}{
		{
			name: "threat detected",
			result: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatType:  ThreatTypeMalware,
				ThreatLevel: ThreatLevelHigh,
			},
			expected: []string{"threat_detection", "threat", string(ThreatTypeMalware), string(ThreatLevelHigh)},
		},
		{
			name: "no threat",
			result: &ThreatAnalysisResult{
				IsThreat: false,
			},
			expected: []string{"threat_detection", "safe", "no_threat"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := auditLogger.generateThreatTags(tt.result)
			assert.Equal(t, tt.expected, tags)
		})
	}
}

func TestAuditLogger_Configuration(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	// Test default configuration
	config := auditLogger.GetConfig()
	assert.True(t, config.Enabled)
	assert.True(t, config.EnableStructuredLogs)
	assert.True(t, config.MaskSensitiveFields)
	assert.Equal(t, 100, config.BufferSize)
	
	// Test configuration update
	newConfig := &AuditConfig{
		Enabled:              false,
		EnableStructuredLogs: false,
		MaskSensitiveFields:  false,
		BufferSize:           50,
		FlushInterval:        10 * time.Second,
		LogRetentionDays:     30,
	}
	
	auditLogger.SetConfig(newConfig)
	updatedConfig := auditLogger.GetConfig()
	
	assert.False(t, updatedConfig.Enabled)
	assert.False(t, updatedConfig.EnableStructuredLogs)
	assert.False(t, updatedConfig.MaskSensitiveFields)
	assert.Equal(t, 50, updatedConfig.BufferSize)
	assert.Equal(t, 10*time.Second, updatedConfig.FlushInterval)
	assert.Equal(t, 30, updatedConfig.LogRetentionDays)
}

func TestAuditLogger_Statistics(t *testing.T) {
	auditLogger, storage := setupTestAuditLogger()
	
	// Mock storage calls
	storage.On("SaveAuditEvent", mock.Anything, mock.AnythingOfType("*ai.AuditEvent")).Return(nil).Times(3)
	
	// Log different types of events
	auditLogger.LogUserAction(context.Background(), "user1", "login", "system", true, "127.0.0.1")
	auditLogger.LogError(context.Background(), "component", "error_type", "message", nil)
	auditLogger.LogSecurityIncident(context.Background(), "incident", "description", AuditSeverityCritical, nil)
	
	stats := auditLogger.GetStats()
	assert.Equal(t, int64(3), stats.TotalEvents)
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventUserAction])
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventError])
	assert.Equal(t, int64(1), stats.EventsByType[AuditEventSecurityIncident])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityInfo])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityError])
	assert.Equal(t, int64(1), stats.EventsBySeverity[AuditSeverityCritical])
	
	// Trigger flush
	auditLogger.FlushNow(context.Background())
	
	storage.AssertExpectations(t)
}

func TestAuditLogger_SensitiveFieldDetection(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	tests := []struct {
		field    string
		expected bool
	}{
		{"password", true},
		{"user_password", true},
		{"PASSWORD", true},
		{"token", true},
		{"auth_token", true},
		{"secret", true},
		{"api_key", true},
		{"credential", true},
		{"username", false},
		{"email", false},
		{"normal_field", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := auditLogger.isSensitiveField(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuditLogger_StringMasking(t *testing.T) {
	auditLogger, _ := setupTestAuditLogger()
	
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "***"},
		{"password123", "pa***23"},
		{"verylongpassword", "ve***rd"},
		{"ab", "***"},
		{"", "***"},
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := auditLogger.maskString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}