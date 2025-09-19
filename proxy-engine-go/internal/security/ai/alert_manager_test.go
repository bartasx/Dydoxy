package ai

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAlertChannel for testing
type MockAlertChannel struct {
	mock.Mock
}

func (m *MockAlertChannel) Send(ctx context.Context, alert *Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockAlertChannel) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAlertChannel) HealthCheck() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAlertChannel) GetConfig() interface{} {
	args := m.Called()
	return args.Get(0)
}

func (m *MockAlertChannel) SetConfig(config interface{}) error {
	args := m.Called(config)
	return args.Error(0)
}

func setupTestAlertManager() *AlertManager {
	config := GetDefaultAlertManagerConfig()
	config.CheckInterval = 100 * time.Millisecond
	config.MaxActiveAlerts = 10
	config.MaxHistorySize = 100
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	return NewAlertManager(config, logger)
}

func createTestAlert(id, metricName string, severity AlertSeverity) *Alert {
	return &Alert{
		ID:          id,
		MetricName:  metricName,
		Severity:    severity,
		Message:     "Test alert message",
		TriggeredAt: time.Now(),
		Status:      AlertStatusActive,
		Labels: map[string]string{
			"component": "test",
		},
		Metadata: map[string]interface{}{
			"test": true,
		},
	}
}

func TestAlertManager_Creation(t *testing.T) {
	manager := setupTestAlertManager()
	
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.config)
	assert.NotNil(t, manager.channels)
	assert.NotNil(t, manager.activeAlerts)
	assert.NotNil(t, manager.alertHistory)
	assert.True(t, manager.config.Enabled)
}

func TestAlertManager_SendAlert(t *testing.T) {
	manager := setupTestAlertManager()
	
	// Add mock channel
	mockChannel := &MockAlertChannel{}
	mockChannel.On("Name").Return("test")
	mockChannel.On("Send", mock.Anything, mock.Anything).Return(nil)
	manager.AddChannel("test", mockChannel)
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	err := manager.SendAlert(alert)
	assert.NoError(t, err)
	
	// Check that alert is active
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
	assert.Contains(t, activeAlerts, "test-alert-1")
	
	// Check alert history
	history := manager.GetAlertHistory(10)
	assert.Len(t, history, 1)
	assert.Equal(t, AlertEventTriggered, history[0].Type)
	
	mockChannel.AssertExpectations(t)
}

func TestAlertManager_ResolveAlert(t *testing.T) {
	manager := setupTestAlertManager()
	
	// Add mock channel
	mockChannel := &MockAlertChannel{}
	mockChannel.On("Name").Return("test")
	mockChannel.On("Send", mock.Anything, mock.Anything).Return(nil)
	manager.AddChannel("test", mockChannel)
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert
	err := manager.SendAlert(alert)
	require.NoError(t, err)
	
	// Resolve alert
	err = manager.ResolveAlert("test-alert-1")
	assert.NoError(t, err)
	
	// Check that alert is no longer active
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 0)
	
	// Check alert history
	history := manager.GetAlertHistory(10)
	assert.Len(t, history, 2) // Triggered + Resolved
	assert.Equal(t, AlertEventResolved, history[1].Type)
	
	mockChannel.AssertExpectations(t)
}

func TestAlertManager_AcknowledgeAlert(t *testing.T) {
	manager := setupTestAlertManager()
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert
	err := manager.SendAlert(alert)
	require.NoError(t, err)
	
	// Acknowledge alert
	err = manager.AcknowledgeAlert("test-alert-1", "test-user")
	assert.NoError(t, err)
	
	// Check that alert is acknowledged
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
	activeAlert := activeAlerts["test-alert-1"]
	assert.Equal(t, "test-user", activeAlert.AckBy)
	assert.NotNil(t, activeAlert.AckAt)
	
	// Check alert history
	history := manager.GetAlertHistory(10)
	assert.Len(t, history, 2) // Triggered + Acknowledged
	assert.Equal(t, AlertEventAcknowledged, history[1].Type)
}

func TestAlertManager_SilenceAlert(t *testing.T) {
	manager := setupTestAlertManager()
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert
	err := manager.SendAlert(alert)
	require.NoError(t, err)
	
	// Silence alert
	duration := 1 * time.Hour
	err = manager.SilenceAlert("test-alert-1", duration, "test-user", "Maintenance window")
	assert.NoError(t, err)
	
	// Check that alert is silenced
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
	activeAlert := activeAlerts["test-alert-1"]
	assert.NotNil(t, activeAlert.SilencedUntil)
	assert.True(t, activeAlert.SilencedUntil.After(time.Now()))
	
	// Check alert history
	history := manager.GetAlertHistory(10)
	assert.Len(t, history, 2) // Triggered + Silenced
	assert.Equal(t, AlertEventSilenced, history[1].Type)
}

func TestAlertManager_MaxActiveAlerts(t *testing.T) {
	manager := setupTestAlertManager()
	manager.config.MaxActiveAlerts = 2
	
	// Send alerts up to the limit
	for i := 0; i < 2; i++ {
		alert := createTestAlert(fmt.Sprintf("test-alert-%d", i), "cpu_usage", AlertSeverityWarning)
		err := manager.SendAlert(alert)
		assert.NoError(t, err)
	}
	
	// Try to send one more alert (should fail)
	alert := createTestAlert("test-alert-overflow", "cpu_usage", AlertSeverityWarning)
	err := manager.SendAlert(alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum active alerts reached")
	
	// Check active alerts count
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 2)
}

func TestAlertManager_ChannelManagement(t *testing.T) {
	manager := setupTestAlertManager()
	
	mockChannel1 := &MockAlertChannel{}
	mockChannel1.On("Name").Return("channel1")
	mockChannel1.On("HealthCheck").Return(nil)
	
	mockChannel2 := &MockAlertChannel{}
	mockChannel2.On("Name").Return("channel2")
	mockChannel2.On("HealthCheck").Return(nil)
	
	// Add channels
	manager.AddChannel("channel1", mockChannel1)
	manager.AddChannel("channel2", mockChannel2)
	
	// Check channel status
	status := manager.GetChannelStatus()
	assert.Len(t, status, 2)
	assert.NoError(t, status["channel1"])
	assert.NoError(t, status["channel2"])
	
	// Remove channel
	manager.RemoveChannel("channel1")
	status = manager.GetChannelStatus()
	assert.Len(t, status, 1)
	assert.Contains(t, status, "channel2")
	
	mockChannel1.AssertExpectations(t)
	mockChannel2.AssertExpectations(t)
}

func TestAlertManager_EscalationRules(t *testing.T) {
	manager := setupTestAlertManager()
	manager.config.EscalationEnabled = true
	
	// Add escalation rule
	rule := EscalationRule{
		Condition:   "severity >= warning",
		Delay:       100 * time.Millisecond,
		Channels:    []string{"test"},
		RepeatCount: 2,
		RepeatDelay: 50 * time.Millisecond,
	}
	manager.AddEscalationRule(rule)
	
	// Add mock channel
	mockChannel := &MockAlertChannel{}
	mockChannel.On("Name").Return("test")
	mockChannel.On("Send", mock.Anything, mock.Anything).Return(nil)
	manager.AddChannel("test", mockChannel)
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert
	err := manager.SendAlert(alert)
	require.NoError(t, err)
	
	// Wait for escalation
	time.Sleep(150 * time.Millisecond)
	
	// Check that alert was escalated
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
	activeAlert := activeAlerts["test-alert-1"]
	assert.Greater(t, activeAlert.EscalationLevel, 0)
	
	mockChannel.AssertExpectations(t)
}

func TestAlertManager_SilenceRules(t *testing.T) {
	manager := setupTestAlertManager()
	
	// Add silence rule
	silenceRule := SilenceRule{
		ID:      "test-silence",
		Enabled: true,
		Name:    "Test Silence",
		Matchers: []AlertMatcher{
			{
				Name:     "component",
				Value:    "test",
				Operator: MatcherEqual,
			},
		},
		StartsAt: time.Now().Add(-1 * time.Hour),
		EndsAt:   time.Now().Add(1 * time.Hour),
	}
	manager.AddSilenceRule(silenceRule)
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert (should be silenced)
	err := manager.SendAlert(alert)
	assert.NoError(t, err)
	
	// Check that no alert is active (silenced)
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 0)
}

func TestAlertManager_AlertMatching(t *testing.T) {
	manager := setupTestAlertManager()
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	alert.Labels["environment"] = "production"
	
	tests := []struct {
		name     string
		matchers []AlertMatcher
		expected bool
	}{
		{
			name: "exact match",
			matchers: []AlertMatcher{
				{Name: "component", Value: "test", Operator: MatcherEqual},
			},
			expected: true,
		},
		{
			name: "not equal match",
			matchers: []AlertMatcher{
				{Name: "component", Value: "other", Operator: MatcherNotEqual},
			},
			expected: true,
		},
		{
			name: "regex match",
			matchers: []AlertMatcher{
				{Name: "environment", Value: "prod", Operator: MatcherRegex},
			},
			expected: true,
		},
		{
			name: "multiple matchers - all match",
			matchers: []AlertMatcher{
				{Name: "component", Value: "test", Operator: MatcherEqual},
				{Name: "environment", Value: "production", Operator: MatcherEqual},
			},
			expected: true,
		},
		{
			name: "multiple matchers - one doesn't match",
			matchers: []AlertMatcher{
				{Name: "component", Value: "test", Operator: MatcherEqual},
				{Name: "environment", Value: "staging", Operator: MatcherEqual},
			},
			expected: false,
		},
		{
			name: "severity match",
			matchers: []AlertMatcher{
				{Name: "severity", Value: "warning", Operator: MatcherEqual},
			},
			expected: true,
		},
		{
			name: "metric name match",
			matchers: []AlertMatcher{
				{Name: "metric_name", Value: "cpu_usage", Operator: MatcherEqual},
			},
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.matchesAlert(tt.matchers, alert)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAlertManager_AlertHistory(t *testing.T) {
	manager := setupTestAlertManager()
	manager.config.MaxHistorySize = 5
	
	// Generate more alerts than history size
	for i := 0; i < 10; i++ {
		alert := createTestAlert(fmt.Sprintf("test-alert-%d", i), "cpu_usage", AlertSeverityWarning)
		err := manager.SendAlert(alert)
		require.NoError(t, err)
	}
	
	// Check that history is limited
	history := manager.GetAlertHistory(100)
	assert.Len(t, history, 5) // Should be limited by MaxHistorySize
	
	// Check that we get the most recent events
	limitedHistory := manager.GetAlertHistory(3)
	assert.Len(t, limitedHistory, 3)
}

func TestAlertManager_NotificationLogging(t *testing.T) {
	manager := setupTestAlertManager()
	
	// Add mock channel that fails
	mockChannel := &MockAlertChannel{}
	mockChannel.On("Name").Return("test")
	mockChannel.On("Send", mock.Anything, mock.Anything).Return(assert.AnError)
	manager.AddChannel("test", mockChannel)
	
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	
	// Send alert (notification will fail)
	err := manager.SendAlert(alert)
	assert.Error(t, err)
	
	// Check notification log
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
	activeAlert := activeAlerts["test-alert-1"]
	assert.Len(t, activeAlert.NotificationLog, 1)
	
	notificationLog := activeAlert.NotificationLog[0]
	assert.Equal(t, "test", notificationLog.Channel)
	assert.False(t, notificationLog.Success)
	assert.NotEmpty(t, notificationLog.Error)
	assert.Equal(t, 1, notificationLog.Attempt)
	
	mockChannel.AssertExpectations(t)
}

func TestAlertManager_StartStop(t *testing.T) {
	manager := setupTestAlertManager()
	
	// Start manager
	err := manager.Start()
	assert.NoError(t, err)
	
	// Stop manager
	err = manager.Stop()
	assert.NoError(t, err)
}

func TestAlertManager_DisabledManager(t *testing.T) {
	config := GetDefaultAlertManagerConfig()
	config.Enabled = false
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	manager := NewAlertManager(config, logger)
	
	// Start should succeed but do nothing
	err := manager.Start()
	assert.NoError(t, err)
	
	// Send alert should do nothing
	alert := createTestAlert("test-alert-1", "cpu_usage", AlertSeverityWarning)
	err = manager.SendAlert(alert)
	assert.NoError(t, err)
	
	// No alerts should be active
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 0)
}

func TestAlertManager_ChannelFiltering(t *testing.T) {
	manager := setupTestAlertManager()
	
	tests := []struct {
		name         string
		channelName  string
		severity     AlertSeverity
		escalation   int
		shouldSend   bool
	}{
		{"email - info", "email", AlertSeverityInfo, 0, false},
		{"email - warning", "email", AlertSeverityWarning, 0, true},
		{"email - error", "email", AlertSeverityError, 0, true},
		{"slack - info", "slack", AlertSeverityInfo, 0, false},
		{"slack - warning", "slack", AlertSeverityWarning, 0, true},
		{"webhook - info", "webhook", AlertSeverityInfo, 0, true},
		{"webhook - warning", "webhook", AlertSeverityWarning, 0, true},
		{"pagerduty - warning", "pagerduty", AlertSeverityWarning, 0, false},
		{"pagerduty - error", "pagerduty", AlertSeverityError, 0, true},
		{"pagerduty - escalated", "pagerduty", AlertSeverityWarning, 1, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.shouldSendToChannel(tt.channelName, tt.severity, tt.escalation)
			assert.Equal(t, tt.shouldSend, result)
		})
	}
}

func TestAlertManager_DefaultConfig(t *testing.T) {
	config := GetDefaultAlertManagerConfig()
	
	assert.True(t, config.Enabled)
	assert.Equal(t, AlertSeverityWarning, config.DefaultSeverity)
	assert.Equal(t, 7*24*time.Hour, config.AlertRetentionPeriod)
	assert.Equal(t, 1000, config.MaxActiveAlerts)
	assert.Equal(t, 10000, config.MaxHistorySize)
	assert.Equal(t, 30*time.Second, config.CheckInterval)
	assert.True(t, config.EscalationEnabled)
	assert.NotNil(t, config.Channels)
	assert.NotNil(t, config.GlobalLabels)
	assert.NotNil(t, config.SilenceRules)
	assert.Equal(t, "ai-threat-detection", config.GlobalLabels["service"])
}