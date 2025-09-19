package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AlertManager manages operational alerts for the AI threat detection system
type AlertManager struct {
	config          *AlertManagerConfig
	channels        map[string]AlertChannel
	escalationRules []EscalationRule
	activeAlerts    map[string]*ActiveAlert
	alertHistory    []*AlertEvent
	logger          *logrus.Logger
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
}

// AlertManagerConfig holds configuration for the alert manager
type AlertManagerConfig struct {
	Enabled              bool                   `json:"enabled"`
	DefaultSeverity      AlertSeverity          `json:"default_severity"`
	AlertRetentionPeriod time.Duration          `json:"alert_retention_period"`
	MaxActiveAlerts      int                    `json:"max_active_alerts"`
	MaxHistorySize       int                    `json:"max_history_size"`
	CheckInterval        time.Duration          `json:"check_interval"`
	EscalationEnabled    bool                   `json:"escalation_enabled"`
	Channels             map[string]interface{} `json:"channels"`
	GlobalLabels         map[string]string      `json:"global_labels"`
	SilenceRules         []SilenceRule          `json:"silence_rules"`
}

// ActiveAlert represents an active alert with escalation state
type ActiveAlert struct {
	Alert           *Alert            `json:"alert"`
	EscalationLevel int               `json:"escalation_level"`
	LastEscalated   time.Time         `json:"last_escalated"`
	NotificationLog []NotificationLog `json:"notification_log"`
	SilencedUntil   *time.Time        `json:"silenced_until,omitempty"`
	AckBy           string            `json:"ack_by,omitempty"`
	AckAt           *time.Time        `json:"ack_at,omitempty"`
}

// NotificationLog tracks notification attempts
type NotificationLog struct {
	Channel   string    `json:"channel"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Attempt   int       `json:"attempt"`
}

// AlertEvent represents a historical alert event
type AlertEvent struct {
	ID        string                 `json:"id"`
	Type      AlertEventType         `json:"type"`
	Alert     *Alert                 `json:"alert"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// AlertEventType defines types of alert events
type AlertEventType string

const (
	AlertEventTriggered  AlertEventType = "triggered"
	AlertEventResolved   AlertEventType = "resolved"
	AlertEventEscalated  AlertEventType = "escalated"
	AlertEventSilenced   AlertEventType = "silenced"
	AlertEventAcknowledged AlertEventType = "acknowledged"
)

// SilenceRule defines conditions for silencing alerts
type SilenceRule struct {
	ID          string            `json:"id"`
	Enabled     bool              `json:"enabled"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Matchers    []AlertMatcher    `json:"matchers"`
	StartsAt    time.Time         `json:"starts_at"`
	EndsAt      time.Time         `json:"ends_at"`
	CreatedBy   string            `json:"created_by"`
	Comment     string            `json:"comment"`
}

// AlertMatcher defines conditions for matching alerts
type AlertMatcher struct {
	Name     string      `json:"name"`
	Value    string      `json:"value"`
	Operator MatcherType `json:"operator"`
}

// MatcherType defines types of alert matchers
type MatcherType string

const (
	MatcherEqual    MatcherType = "="
	MatcherNotEqual MatcherType = "!="
	MatcherRegex    MatcherType = "=~"
	MatcherNotRegex MatcherType = "!~"
)

// AlertChannel interface for sending notifications
type AlertChannel interface {
	Send(ctx context.Context, alert *Alert) error
	Name() string
	HealthCheck() error
	GetConfig() interface{}
	SetConfig(config interface{}) error
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertManagerConfig, logger *logrus.Logger) *AlertManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &AlertManager{
		config:          config,
		channels:        make(map[string]AlertChannel),
		escalationRules: make([]EscalationRule, 0),
		activeAlerts:    make(map[string]*ActiveAlert),
		alertHistory:    make([]*AlertEvent, 0),
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start starts the alert manager
func (am *AlertManager) Start() error {
	if !am.config.Enabled {
		am.logger.Info("Alert manager is disabled")
		return nil
	}

	am.logger.Info("Starting alert manager")

	// Initialize channels from config
	if err := am.initializeChannels(); err != nil {
		return fmt.Errorf("failed to initialize alert channels: %w", err)
	}

	// Start background processes
	go am.runEscalationLoop()
	go am.runCleanupLoop()
	go am.runHealthCheckLoop()

	return nil
}

// Stop stops the alert manager
func (am *AlertManager) Stop() error {
	am.logger.Info("Stopping alert manager")
	am.cancel()
	return nil
}

// SendAlert sends an alert through the alert manager
func (am *AlertManager) SendAlert(alert *Alert) error {
	if !am.config.Enabled {
		return nil
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if alert should be silenced
	if am.isAlertSilenced(alert) {
		am.logger.Debugf("Alert %s is silenced, skipping", alert.ID)
		return nil
	}

	// Check if this is a new alert or update to existing
	existingAlert, exists := am.activeAlerts[alert.ID]
	if exists {
		// Update existing alert
		existingAlert.Alert = alert
		am.logAlertEvent(AlertEventTriggered, alert, map[string]interface{}{
			"updated": true,
		})
	} else {
		// New alert
		if len(am.activeAlerts) >= am.config.MaxActiveAlerts {
			am.logger.Warnf("Maximum active alerts reached (%d), dropping alert %s", 
				am.config.MaxActiveAlerts, alert.ID)
			return fmt.Errorf("maximum active alerts reached")
		}

		am.activeAlerts[alert.ID] = &ActiveAlert{
			Alert:           alert,
			EscalationLevel: 0,
			LastEscalated:   time.Now(),
			NotificationLog: make([]NotificationLog, 0),
		}

		am.logAlertEvent(AlertEventTriggered, alert, nil)
	}

	// Send initial notifications
	return am.sendNotifications(alert, 0)
}

// ResolveAlert resolves an active alert
func (am *AlertManager) ResolveAlert(alertID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	activeAlert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert %s not found", alertID)
	}

	// Update alert status
	now := time.Now()
	activeAlert.Alert.Status = AlertStatusResolved
	activeAlert.Alert.ResolvedAt = &now

	// Log resolution event
	am.logAlertEvent(AlertEventResolved, activeAlert.Alert, nil)

	// Send resolution notifications
	am.sendResolutionNotifications(activeAlert.Alert)

	// Remove from active alerts
	delete(am.activeAlerts, alertID)

	am.logger.Infof("Alert %s resolved", alertID)
	return nil
}

// AcknowledgeAlert acknowledges an alert
func (am *AlertManager) AcknowledgeAlert(alertID, acknowledgedBy string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	activeAlert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert %s not found", alertID)
	}

	now := time.Now()
	activeAlert.AckBy = acknowledgedBy
	activeAlert.AckAt = &now

	am.logAlertEvent(AlertEventAcknowledged, activeAlert.Alert, map[string]interface{}{
		"acknowledged_by": acknowledgedBy,
	})

	am.logger.Infof("Alert %s acknowledged by %s", alertID, acknowledgedBy)
	return nil
}

// SilenceAlert silences an alert for a specified duration
func (am *AlertManager) SilenceAlert(alertID string, duration time.Duration, silencedBy, reason string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	activeAlert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert %s not found", alertID)
	}

	silencedUntil := time.Now().Add(duration)
	activeAlert.SilencedUntil = &silencedUntil

	am.logAlertEvent(AlertEventSilenced, activeAlert.Alert, map[string]interface{}{
		"silenced_by":    silencedBy,
		"reason":         reason,
		"silenced_until": silencedUntil,
	})

	am.logger.Infof("Alert %s silenced until %v by %s: %s", 
		alertID, silencedUntil, silencedBy, reason)
	return nil
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() map[string]*ActiveAlert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Create a copy to avoid race conditions
	alerts := make(map[string]*ActiveAlert)
	for k, v := range am.activeAlerts {
		alerts[k] = v
	}
	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*AlertEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	// Return most recent events
	start := len(am.alertHistory) - limit
	if start < 0 {
		start = 0
	}

	history := make([]*AlertEvent, limit)
	copy(history, am.alertHistory[start:])
	return history
}

// AddChannel adds an alert channel
func (am *AlertManager) AddChannel(name string, channel AlertChannel) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.channels[name] = channel
	am.logger.Infof("Added alert channel: %s", name)
}

// RemoveChannel removes an alert channel
func (am *AlertManager) RemoveChannel(name string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.channels, name)
	am.logger.Infof("Removed alert channel: %s", name)
}

// AddEscalationRule adds an escalation rule
func (am *AlertManager) AddEscalationRule(rule EscalationRule) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.escalationRules = append(am.escalationRules, rule)
	am.logger.Infof("Added escalation rule: %s", rule.Condition)
}

// AddSilenceRule adds a silence rule
func (am *AlertManager) AddSilenceRule(rule SilenceRule) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.config.SilenceRules = append(am.config.SilenceRules, rule)
	am.logger.Infof("Added silence rule: %s", rule.Name)
}

// GetChannelStatus returns the status of all channels
func (am *AlertManager) GetChannelStatus() map[string]error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	status := make(map[string]error)
	for name, channel := range am.channels {
		status[name] = channel.HealthCheck()
	}
	return status
}

// Private methods

func (am *AlertManager) initializeChannels() error {
	// Initialize email channel if configured
	if emailConfig, ok := am.config.Channels["email"]; ok {
		if configMap, ok := emailConfig.(map[string]interface{}); ok {
			channel, err := NewEmailAlertChannel(configMap, am.logger)
			if err != nil {
				return fmt.Errorf("failed to create email channel: %w", err)
			}
			am.channels["email"] = channel
		}
	}

	// Initialize Slack channel if configured
	if slackConfig, ok := am.config.Channels["slack"]; ok {
		if configMap, ok := slackConfig.(map[string]interface{}); ok {
			channel, err := NewSlackAlertChannel(configMap, am.logger)
			if err != nil {
				return fmt.Errorf("failed to create slack channel: %w", err)
			}
			am.channels["slack"] = channel
		}
	}

	// Initialize webhook channel if configured
	if webhookConfig, ok := am.config.Channels["webhook"]; ok {
		if configMap, ok := webhookConfig.(map[string]interface{}); ok {
			channel, err := NewWebhookAlertChannel(configMap, am.logger)
			if err != nil {
				return fmt.Errorf("failed to create webhook channel: %w", err)
			}
			am.channels["webhook"] = channel
		}
	}

	// Initialize PagerDuty channel if configured
	if pagerDutyConfig, ok := am.config.Channels["pagerduty"]; ok {
		if configMap, ok := pagerDutyConfig.(map[string]interface{}); ok {
			channel, err := NewPagerDutyAlertChannel(configMap, am.logger)
			if err != nil {
				return fmt.Errorf("failed to create pagerduty channel: %w", err)
			}
			am.channels["pagerduty"] = channel
		}
	}

	am.logger.Infof("Initialized %d alert channels", len(am.channels))
	return nil
}

func (am *AlertManager) sendNotifications(alert *Alert, escalationLevel int) error {
	var errors []error

	for channelName, channel := range am.channels {
		// Check if channel should receive this alert based on severity
		if !am.shouldSendToChannel(channelName, alert.Severity, escalationLevel) {
			continue
		}

		// Send notification
		err := am.sendToChannel(channel, alert)
		
		// Log notification attempt
		am.logNotificationAttempt(alert.ID, channelName, err == nil, err)
		
		if err != nil {
			errors = append(errors, fmt.Errorf("channel %s: %w", channelName, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %v", errors)
	}

	return nil
}

func (am *AlertManager) sendToChannel(channel AlertChannel, alert *Alert) error {
	ctx, cancel := context.WithTimeout(am.ctx, 30*time.Second)
	defer cancel()

	return channel.Send(ctx, alert)
}

func (am *AlertManager) sendResolutionNotifications(alert *Alert) {
	for channelName, channel := range am.channels {
		// Create resolution alert
		resolutionAlert := &Alert{
			ID:          alert.ID + "_resolved",
			MetricName:  alert.MetricName,
			Severity:    AlertSeverityInfo,
			Message:     fmt.Sprintf("RESOLVED: %s", alert.Message),
			TriggeredAt: time.Now(),
			Status:      AlertStatusResolved,
			Labels:      alert.Labels,
			Metadata: map[string]interface{}{
				"original_alert_id": alert.ID,
				"resolution_time":   time.Now(),
			},
		}

		err := am.sendToChannel(channel, resolutionAlert)
		am.logNotificationAttempt(alert.ID, channelName+"_resolution", err == nil, err)
	}
}

func (am *AlertManager) shouldSendToChannel(channelName string, severity AlertSeverity, escalationLevel int) bool {
	// Basic severity filtering - can be enhanced with more complex rules
	switch channelName {
	case "email":
		return severity >= AlertSeverityWarning
	case "slack":
		return severity >= AlertSeverityWarning
	case "webhook":
		return true // Send all alerts to webhooks
	case "pagerduty":
		return severity >= AlertSeverityError || escalationLevel > 0
	default:
		return true
	}
}

func (am *AlertManager) logNotificationAttempt(alertID, channel string, success bool, err error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	activeAlert, exists := am.activeAlerts[alertID]
	if !exists {
		return
	}

	logEntry := NotificationLog{
		Channel:   channel,
		Timestamp: time.Now(),
		Success:   success,
		Attempt:   len(activeAlert.NotificationLog) + 1,
	}

	if err != nil {
		logEntry.Error = err.Error()
	}

	activeAlert.NotificationLog = append(activeAlert.NotificationLog, logEntry)
}

func (am *AlertManager) logAlertEvent(eventType AlertEventType, alert *Alert, metadata map[string]interface{}) {
	event := &AlertEvent{
		ID:        fmt.Sprintf("%s_%s_%d", alert.ID, eventType, time.Now().UnixNano()),
		Type:      eventType,
		Alert:     alert,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}

	am.alertHistory = append(am.alertHistory, event)

	// Trim history if it exceeds max size
	if len(am.alertHistory) > am.config.MaxHistorySize {
		am.alertHistory = am.alertHistory[len(am.alertHistory)-am.config.MaxHistorySize:]
	}
}

func (am *AlertManager) isAlertSilenced(alert *Alert) bool {
	for _, rule := range am.config.SilenceRules {
		if !rule.Enabled {
			continue
		}

		now := time.Now()
		if now.Before(rule.StartsAt) || now.After(rule.EndsAt) {
			continue
		}

		if am.matchesAlert(rule.Matchers, alert) {
			return true
		}
	}
	return false
}

func (am *AlertManager) matchesAlert(matchers []AlertMatcher, alert *Alert) bool {
	for _, matcher := range matchers {
		var value string
		
		switch matcher.Name {
		case "metric_name":
			value = alert.MetricName
		case "severity":
			value = string(alert.Severity)
		case "status":
			value = string(alert.Status)
		default:
			if labelValue, exists := alert.Labels[matcher.Name]; exists {
				value = labelValue
			}
		}

		if !am.matcherMatches(matcher, value) {
			return false
		}
	}
	return true
}

func (am *AlertManager) matcherMatches(matcher AlertMatcher, value string) bool {
	switch matcher.Operator {
	case MatcherEqual:
		return value == matcher.Value
	case MatcherNotEqual:
		return value != matcher.Value
	case MatcherRegex:
		// Simplified regex matching - would use regexp package in real implementation
		return strings.Contains(value, matcher.Value)
	case MatcherNotRegex:
		return !strings.Contains(value, matcher.Value)
	default:
		return false
	}
}

func (am *AlertManager) runEscalationLoop() {
	if !am.config.EscalationEnabled {
		return
	}

	ticker := time.NewTicker(am.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.processEscalations()
		}
	}
}

func (am *AlertManager) processEscalations() {
	am.mu.Lock()
	defer am.mu.Unlock()

	for alertID, activeAlert := range am.activeAlerts {
		// Skip acknowledged alerts
		if activeAlert.AckAt != nil {
			continue
		}

		// Skip silenced alerts
		if activeAlert.SilencedUntil != nil && time.Now().Before(*activeAlert.SilencedUntil) {
			continue
		}

		// Check if escalation is needed
		for _, rule := range am.escalationRules {
			if am.shouldEscalate(activeAlert, rule) {
				am.escalateAlert(alertID, activeAlert, rule)
				break
			}
		}
	}
}

func (am *AlertManager) shouldEscalate(activeAlert *ActiveAlert, rule EscalationRule) bool {
	// Check if enough time has passed since last escalation
	if time.Since(activeAlert.LastEscalated) < rule.Delay {
		return false
	}

	// Check if we haven't exceeded repeat count
	if rule.RepeatCount > 0 && activeAlert.EscalationLevel >= rule.RepeatCount {
		return false
	}

	// Additional condition checking would go here
	return true
}

func (am *AlertManager) escalateAlert(alertID string, activeAlert *ActiveAlert, rule EscalationRule) {
	activeAlert.EscalationLevel++
	activeAlert.LastEscalated = time.Now()

	// Send escalation notifications
	am.sendNotifications(activeAlert.Alert, activeAlert.EscalationLevel)

	am.logAlertEvent(AlertEventEscalated, activeAlert.Alert, map[string]interface{}{
		"escalation_level": activeAlert.EscalationLevel,
		"rule":             rule.Condition,
	})

	am.logger.Warnf("Alert %s escalated to level %d", alertID, activeAlert.EscalationLevel)
}

func (am *AlertManager) runCleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.cleanupOldAlerts()
		}
	}
}

func (am *AlertManager) cleanupOldAlerts() {
	am.mu.Lock()
	defer am.mu.Unlock()

	cutoff := time.Now().Add(-am.config.AlertRetentionPeriod)

	// Clean up alert history
	var newHistory []*AlertEvent
	for _, event := range am.alertHistory {
		if event.Timestamp.After(cutoff) {
			newHistory = append(newHistory, event)
		}
	}
	am.alertHistory = newHistory

	am.logger.Debugf("Cleaned up old alerts, %d events remaining", len(am.alertHistory))
}

func (am *AlertManager) runHealthCheckLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.performHealthChecks()
		}
	}
}

func (am *AlertManager) performHealthChecks() {
	am.mu.RLock()
	channels := make(map[string]AlertChannel)
	for k, v := range am.channels {
		channels[k] = v
	}
	am.mu.RUnlock()

	for name, channel := range channels {
		if err := channel.HealthCheck(); err != nil {
			am.logger.Errorf("Health check failed for channel %s: %v", name, err)
		}
	}
}

// GetDefaultAlertManagerConfig returns default configuration
func GetDefaultAlertManagerConfig() *AlertManagerConfig {
	return &AlertManagerConfig{
		Enabled:              true,
		DefaultSeverity:      AlertSeverityWarning,
		AlertRetentionPeriod: 7 * 24 * time.Hour,
		MaxActiveAlerts:      1000,
		MaxHistorySize:       10000,
		CheckInterval:        30 * time.Second,
		EscalationEnabled:    true,
		Channels:             make(map[string]interface{}),
		GlobalLabels: map[string]string{
			"service": "ai-threat-detection",
		},
		SilenceRules: make([]SilenceRule, 0),
	}
}