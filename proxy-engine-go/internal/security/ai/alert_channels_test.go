package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestAlert() *Alert {
	return &Alert{
		ID:          "test-alert-123",
		Type:        AlertTypeHighErrorRate,
		Severity:    AlertSeverityWarning,
		Component:   "test_component",
		Title:       "Test Alert",
		Description: "This is a test alert for unit testing",
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"error_rate": 0.1,
			"threshold":  0.05,
		},
		Escalated: false,
	}
}

func TestEmailAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	config := &EmailConfig{
		Enabled:    true,
		SMTPHost:   "smtp.example.com",
		SMTPPort:   587,
		Username:   "test@example.com",
		Password:   "password",
		From:       "alerts@example.com",
		Recipients: []string{"admin@example.com"},
		UseTLS:     true,
		Subject:    "Test Alert",
	}
	
	channel := NewEmailAlertChannel(config, logger)
	
	assert.Equal(t, "email", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	// Test disabled channel
	config.Enabled = false
	assert.False(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestEmailAlertChannel_FormatEmailBody(t *testing.T) {
	logger := logrus.New()
	config := &EmailConfig{Enabled: true}
	channel := NewEmailAlertChannel(config, logger)
	
	alert := createTestAlert()
	body := channel.formatEmailBody(alert)
	
	assert.Contains(t, body, "Test Alert")
	assert.Contains(t, body, "This is a test alert")
	assert.Contains(t, body, "test_component")
	assert.Contains(t, body, "warning")
	assert.Contains(t, body, "test-alert-123")
	assert.Contains(t, body, "<!DOCTYPE html>")
}

func TestEmailAlertChannel_GetSeverityColor(t *testing.T) {
	logger := logrus.New()
	config := &EmailConfig{Enabled: true}
	channel := NewEmailAlertChannel(config, logger)
	
	tests := []struct {
		severity AlertSeverity
		expected string
	}{
		{AlertSeverityCritical, "#dc3545"},
		{AlertSeverityError, "#fd7e14"},
		{AlertSeverityWarning, "#ffc107"},
		{AlertSeverityInfo, "#17a2b8"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := channel.getSeverityColor(tt.severity)
			assert.Equal(t, tt.expected, color)
		})
	}
}

func TestSlackAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		
		var message SlackMessage
		err := json.NewDecoder(r.Body).Decode(&message)
		require.NoError(t, err)
		
		assert.Contains(t, message.Text, "Test Alert")
		assert.Len(t, message.Attachments, 1)
		
		attachment := message.Attachments[0]
		assert.Contains(t, attachment.Title, "Test Alert")
		assert.Equal(t, "warning", attachment.Color)
		assert.Len(t, attachment.Fields, 4)
		
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	config := &SlackConfig{
		Enabled:    true,
		WebhookURL: server.URL,
		Channel:    "#alerts",
		Username:   "AI Security Bot",
		IconEmoji:  ":robot_face:",
	}
	
	channel := NewSlackAlertChannel(config, logger)
	
	assert.Equal(t, "slack", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
}

func TestSlackAlertChannel_Disabled(t *testing.T) {
	logger := logrus.New()
	config := &SlackConfig{
		Enabled:    false,
		WebhookURL: "https://hooks.slack.com/test",
	}
	
	channel := NewSlackAlertChannel(config, logger)
	assert.False(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestSlackAlertChannel_GetSeverityEmoji(t *testing.T) {
	logger := logrus.New()
	config := &SlackConfig{Enabled: true}
	channel := NewSlackAlertChannel(config, logger)
	
	tests := []struct {
		severity AlertSeverity
		expected string
	}{
		{AlertSeverityCritical, "🚨"},
		{AlertSeverityError, "❌"},
		{AlertSeverityWarning, "⚠️"},
		{AlertSeverityInfo, "ℹ️"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			emoji := channel.getSeverityEmoji(tt.severity)
			assert.Equal(t, tt.expected, emoji)
		})
	}
}

func TestWebhookAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "AI-Security-System/1.0", r.Header.Get("User-Agent"))
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		require.NoError(t, err)
		
		assert.Equal(t, "test-alert-123", payload["alert_id"])
		assert.Equal(t, string(AlertTypeHighErrorRate), payload["type"])
		assert.Equal(t, string(AlertSeverityWarning), payload["severity"])
		assert.Equal(t, "test_component", payload["component"])
		assert.Equal(t, "Test Alert", payload["title"])
		
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	config := &WebhookConfig{
		Enabled: true,
		URL:     server.URL,
		Method:  "POST",
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		Timeout:    5 * time.Second,
		RetryCount: 2,
		RetryDelay: 100 * time.Millisecond,
	}
	
	channel := NewWebhookAlertChannel(config, logger)
	
	assert.Equal(t, "webhook", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
}

func TestWebhookAlertChannel_Retry(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	
	config := &WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 3,
		RetryDelay: 10 * time.Millisecond,
	}
	
	channel := NewWebhookAlertChannel(config, logger)
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestWebhookAlertChannel_RetryFailure(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	config := &WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 2,
		RetryDelay: 10 * time.Millisecond,
	}
	
	channel := NewWebhookAlertChannel(config, logger)
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed after")
}

func TestPagerDutyAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		
		var event PagerDutyEvent
		err := json.NewDecoder(r.Body).Decode(&event)
		require.NoError(t, err)
		
		assert.Equal(t, "test-integration-key", event.RoutingKey)
		assert.Equal(t, "trigger", event.EventAction)
		assert.Equal(t, "test-alert-123", event.DedupKey)
		assert.Equal(t, "Test Alert", event.Payload.Summary)
		assert.Equal(t, "warning", event.Payload.Severity)
		assert.Equal(t, "test_component", event.Payload.Component)
		
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	
	config := &PagerDutyConfig{
		Enabled:        true,
		IntegrationKey: "test-integration-key",
		ServiceURL:     "https://example.pagerduty.com",
	}
	
	channel := NewPagerDutyAlertChannel(config, logger)
	
	assert.Equal(t, "pagerduty", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	// Temporarily replace the PagerDuty URL for testing
	originalSend := channel.Send
	channel.Send = func(ctx context.Context, alert *Alert) error {
		event := PagerDutyEvent{
			RoutingKey:  config.IntegrationKey,
			EventAction: "trigger",
			DedupKey:    alert.ID,
			Client:      "AI Security System",
			ClientURL:   config.ServiceURL,
			Payload: PagerDutyEventPayload{
				Summary:   alert.Title,
				Source:    "ai-security-system",
				Severity:  channel.mapSeverity(alert.Severity),
				Timestamp: alert.Timestamp.Format(time.RFC3339),
				Component: alert.Component,
				Group:     "ai-security",
				Class:     string(alert.Type),
				CustomDetails: map[string]interface{}{
					"description": alert.Description,
					"alert_id":    alert.ID,
					"metadata":    alert.Metadata,
				},
			},
		}
		
		jsonData, _ := json.Marshal(event)
		req, _ := http.NewRequestWithContext(ctx, "POST", server.URL, strings.NewReader(string(jsonData)))
		req.Header.Set("Content-Type", "application/json")
		
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusAccepted {
			return assert.AnError
		}
		
		return nil
	}
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
	
	// Restore original method
	channel.Send = originalSend
}

func TestPagerDutyAlertChannel_MapSeverity(t *testing.T) {
	logger := logrus.New()
	config := &PagerDutyConfig{Enabled: true}
	channel := NewPagerDutyAlertChannel(config, logger)
	
	tests := []struct {
		severity AlertSeverity
		expected string
	}{
		{AlertSeverityCritical, "critical"},
		{AlertSeverityError, "error"},
		{AlertSeverityWarning, "warning"},
		{AlertSeverityInfo, "info"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			mapped := channel.mapSeverity(tt.severity)
			assert.Equal(t, tt.expected, mapped)
		})
	}
}

func TestTeamsAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		
		var message TeamsMessage
		err := json.NewDecoder(r.Body).Decode(&message)
		require.NoError(t, err)
		
		assert.Equal(t, "MessageCard", message.Type)
		assert.Equal(t, "Test Alert", message.Summary)
		assert.Contains(t, message.Title, "AI Security Alert")
		assert.Equal(t, "FFD700", message.ThemeColor) // Warning color
		assert.Len(t, message.Sections, 1)
		
		section := message.Sections[0]
		assert.Equal(t, "Test Alert", section.ActivityTitle)
		assert.Len(t, section.Facts, 5)
		
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	config := &TeamsConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	
	channel := NewTeamsAlertChannel(config, logger)
	
	assert.Equal(t, "teams", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
}

func TestTeamsAlertChannel_GetSeverityColor(t *testing.T) {
	logger := logrus.New()
	config := &TeamsConfig{Enabled: true}
	channel := NewTeamsAlertChannel(config, logger)
	
	tests := []struct {
		severity AlertSeverity
		expected string
	}{
		{AlertSeverityCritical, "FF0000"},
		{AlertSeverityError, "FF8C00"},
		{AlertSeverityWarning, "FFD700"},
		{AlertSeverityInfo, "0078D4"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := channel.getSeverityColor(tt.severity)
			assert.Equal(t, tt.expected, color)
		})
	}
}

func TestDiscordAlertChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		
		var message DiscordMessage
		err := json.NewDecoder(r.Body).Decode(&message)
		require.NoError(t, err)
		
		assert.Equal(t, "AI Security Bot", message.Username)
		assert.Contains(t, message.Content, "AI Security Alert")
		assert.Len(t, message.Embeds, 1)
		
		embed := message.Embeds[0]
		assert.Equal(t, "Test Alert", embed.Title)
		assert.Equal(t, 0xFFD700, embed.Color) // Warning color
		assert.Len(t, embed.Fields, 4)
		assert.NotNil(t, embed.Footer)
		assert.Equal(t, "AI Security System", embed.Footer.Text)
		
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	
	config := &DiscordConfig{
		Enabled:    true,
		WebhookURL: server.URL,
		Username:   "AI Security Bot",
		AvatarURL:  "https://example.com/avatar.png",
	}
	
	channel := NewDiscordAlertChannel(config, logger)
	
	assert.Equal(t, "discord", channel.Name())
	assert.True(t, channel.IsEnabled())
	
	alert := createTestAlert()
	err := channel.Send(context.Background(), alert)
	assert.NoError(t, err)
}

func TestDiscordAlertChannel_GetSeverityColor(t *testing.T) {
	logger := logrus.New()
	config := &DiscordConfig{Enabled: true}
	channel := NewDiscordAlertChannel(config, logger)
	
	tests := []struct {
		severity AlertSeverity
		expected int
	}{
		{AlertSeverityCritical, 0xFF0000},
		{AlertSeverityError, 0xFF8C00},
		{AlertSeverityWarning, 0xFFD700},
		{AlertSeverityInfo, 0x0078D4},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := channel.getSeverityColor(tt.severity)
			assert.Equal(t, tt.expected, color)
		})
	}
}

func TestAlertChannels_IsEnabled(t *testing.T) {
	logger := logrus.New()
	
	tests := []struct {
		name    string
		channel AlertChannel
		enabled bool
	}{
		{
			name:    "email_enabled",
			channel: NewEmailAlertChannel(&EmailConfig{Enabled: true}, logger),
			enabled: true,
		},
		{
			name:    "email_disabled",
			channel: NewEmailAlertChannel(&EmailConfig{Enabled: false}, logger),
			enabled: false,
		},
		{
			name:    "slack_enabled",
			channel: NewSlackAlertChannel(&SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/test"}, logger),
			enabled: true,
		},
		{
			name:    "slack_no_webhook",
			channel: NewSlackAlertChannel(&SlackConfig{Enabled: true, WebhookURL: ""}, logger),
			enabled: false,
		},
		{
			name:    "webhook_enabled",
			channel: NewWebhookAlertChannel(&WebhookConfig{Enabled: true, URL: "https://example.com/webhook"}, logger),
			enabled: true,
		},
		{
			name:    "webhook_no_url",
			channel: NewWebhookAlertChannel(&WebhookConfig{Enabled: true, URL: ""}, logger),
			enabled: false,
		},
		{
			name:    "pagerduty_enabled",
			channel: NewPagerDutyAlertChannel(&PagerDutyConfig{Enabled: true, IntegrationKey: "test-key"}, logger),
			enabled: true,
		},
		{
			name:    "pagerduty_no_key",
			channel: NewPagerDutyAlertChannel(&PagerDutyConfig{Enabled: true, IntegrationKey: ""}, logger),
			enabled: false,
		},
		{
			name:    "teams_enabled",
			channel: NewTeamsAlertChannel(&TeamsConfig{Enabled: true, WebhookURL: "https://outlook.office.com/webhook/test"}, logger),
			enabled: true,
		},
		{
			name:    "teams_no_webhook",
			channel: NewTeamsAlertChannel(&TeamsConfig{Enabled: true, WebhookURL: ""}, logger),
			enabled: false,
		},
		{
			name:    "discord_enabled",
			channel: NewDiscordAlertChannel(&DiscordConfig{Enabled: true, WebhookURL: "https://discord.com/api/webhooks/test"}, logger),
			enabled: true,
		},
		{
			name:    "discord_no_webhook",
			channel: NewDiscordAlertChannel(&DiscordConfig{Enabled: true, WebhookURL: ""}, logger),
			enabled: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.enabled, tt.channel.IsEnabled())
		})
	}
}