package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// EmailAlertChannel sends alerts via email
type EmailAlertChannel struct {
	config *EmailConfig
	logger *logrus.Logger
}

// EmailConfig holds email configuration
type EmailConfig struct {
	Enabled    bool     `json:"enabled"`
	SMTPHost   string   `json:"smtp_host"`
	SMTPPort   int      `json:"smtp_port"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	From       string   `json:"from"`
	Recipients []string `json:"recipients"`
	UseTLS     bool     `json:"use_tls"`
	Subject    string   `json:"subject"`
}

// SlackAlertChannel sends alerts to Slack
type SlackAlertChannel struct {
	config *SlackConfig
	logger *logrus.Logger
}

// SlackConfig holds Slack configuration
type SlackConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
}

// WebhookAlertChannel sends alerts to generic webhooks
type WebhookAlertChannel struct {
	config *WebhookConfig
	client *http.Client
	logger *logrus.Logger
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	Enabled    bool              `json:"enabled"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	Timeout    time.Duration     `json:"timeout"`
	RetryCount int               `json:"retry_count"`
	RetryDelay time.Duration     `json:"retry_delay"`
}

// PagerDutyAlertChannel sends alerts to PagerDuty
type PagerDutyAlertChannel struct {
	config *PagerDutyConfig
	client *http.Client
	logger *logrus.Logger
}

// PagerDutyConfig holds PagerDuty configuration
type PagerDutyConfig struct {
	Enabled        bool   `json:"enabled"`
	IntegrationKey string `json:"integration_key"`
	Severity       string `json:"severity"`
	Source         string `json:"source"`
	Component      string `json:"component"`
	Group          string `json:"group"`
	Class          string `json:"class"`
}

// PagerDutyEvent represents a PagerDuty event
type PagerDutyEvent struct {
	RoutingKey  string                 `json:"routing_key"`
	EventAction string                 `json:"event_action"`
	DedupKey    string                 `json:"dedup_key,omitempty"`
	Payload     PagerDutyEventPayload  `json:"payload"`
	Client      string                 `json:"client,omitempty"`
	ClientURL   string                 `json:"client_url,omitempty"`
	Links       []PagerDutyLink        `json:"links,omitempty"`
	Images      []PagerDutyImage       `json:"images,omitempty"`
}

// PagerDutyEventPayload represents the payload of a PagerDuty event
type PagerDutyEventPayload struct {
	Summary       string                 `json:"summary"`
	Source        string                 `json:"source"`
	Severity      string                 `json:"severity"`
	Timestamp     string                 `json:"timestamp,omitempty"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

// PagerDutyLink represents a link in a PagerDuty event
type PagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

// PagerDutyImage represents an image in a PagerDuty event
type PagerDutyImage struct {
	Src  string `json:"src"`
	Href string `json:"href,omitempty"`
	Alt  string `json:"alt,omitempty"`
}

// SlackMessage represents a Slack message
type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	TitleLink  string       `json:"title_link,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	Timestamp  int64        `json:"ts,omitempty"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// NewEmailAlertChannel creates a new email alert channel
func NewEmailAlertChannel(config map[string]interface{}, logger *logrus.Logger) (*EmailAlertChannel, error) {
	emailConfig := &EmailConfig{}
	
	// Parse configuration - simplified for example
	if enabled, ok := config["enabled"].(bool); ok {
		emailConfig.Enabled = enabled
	}
	if host, ok := config["smtp_host"].(string); ok {
		emailConfig.SMTPHost = host
	}
	if port, ok := config["smtp_port"].(float64); ok {
		emailConfig.SMTPPort = int(port)
	}
	if username, ok := config["username"].(string); ok {
		emailConfig.Username = username
	}
	if password, ok := config["password"].(string); ok {
		emailConfig.Password = password
	}
	if from, ok := config["from"].(string); ok {
		emailConfig.From = from
	}
	if recipients, ok := config["recipients"].([]interface{}); ok {
		for _, r := range recipients {
			if recipient, ok := r.(string); ok {
				emailConfig.Recipients = append(emailConfig.Recipients, recipient)
			}
		}
	}
	if useTLS, ok := config["use_tls"].(bool); ok {
		emailConfig.UseTLS = useTLS
	}
	if subject, ok := config["subject"].(string); ok {
		emailConfig.Subject = subject
	} else {
		emailConfig.Subject = "AI Threat Detection Alert"
	}

	return &EmailAlertChannel{
		config: emailConfig,
		logger: logger,
	}, nil
}

// Send sends an alert via email
func (e *EmailAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !e.config.Enabled {
		return nil
	}

	// Create email message
	subject := fmt.Sprintf("[%s] %s", alert.Severity, e.config.Subject)
	body := e.formatEmailBody(alert)

	// Send email
	auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
	
	for _, recipient := range e.config.Recipients {
		msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", recipient, subject, body)
		
		err := smtp.SendMail(
			fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort),
			auth,
			e.config.From,
			[]string{recipient},
			[]byte(msg),
		)
		
		if err != nil {
			e.logger.Errorf("Failed to send email to %s: %v", recipient, err)
			return err
		}
	}

	e.logger.Infof("Email alert sent for %s", alert.ID)
	return nil
}

// Name returns the channel name
func (e *EmailAlertChannel) Name() string {
	return "email"
}

// HealthCheck checks if the email channel is healthy
func (e *EmailAlertChannel) HealthCheck() error {
	if !e.config.Enabled {
		return nil
	}
	
	// Basic configuration validation
	if e.config.SMTPHost == "" || e.config.From == "" || len(e.config.Recipients) == 0 {
		return fmt.Errorf("email channel misconfigured")
	}
	
	return nil
}

// GetConfig returns the channel configuration
func (e *EmailAlertChannel) GetConfig() interface{} {
	return e.config
}

// SetConfig sets the channel configuration
func (e *EmailAlertChannel) SetConfig(config interface{}) error {
	if emailConfig, ok := config.(*EmailConfig); ok {
		e.config = emailConfig
		return nil
	}
	return fmt.Errorf("invalid config type for email channel")
}

func (e *EmailAlertChannel) formatEmailBody(alert *Alert) string {
	var body strings.Builder
	
	body.WriteString(fmt.Sprintf("Alert ID: %s\n", alert.ID))
	body.WriteString(fmt.Sprintf("Metric: %s\n", alert.MetricName))
	body.WriteString(fmt.Sprintf("Severity: %s\n", alert.Severity))
	body.WriteString(fmt.Sprintf("Status: %s\n", alert.Status))
	body.WriteString(fmt.Sprintf("Message: %s\n", alert.Message))
	body.WriteString(fmt.Sprintf("Triggered At: %s\n", alert.TriggeredAt.Format(time.RFC3339)))
	
	if alert.Threshold != nil {
		body.WriteString(fmt.Sprintf("Threshold: %s %s %.2f\n", 
			alert.Threshold.MetricName, alert.Threshold.Operator, alert.Threshold.Value))
		body.WriteString(fmt.Sprintf("Current Value: %.2f\n", alert.CurrentValue))
	}
	
	if len(alert.Labels) > 0 {
		body.WriteString("\nLabels:\n")
		for k, v := range alert.Labels {
			body.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}
	
	if len(alert.Metadata) > 0 {
		body.WriteString("\nMetadata:\n")
		for k, v := range alert.Metadata {
			body.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}
	
	return body.String()
}

// NewSlackAlertChannel creates a new Slack alert channel
func NewSlackAlertChannel(config map[string]interface{}, logger *logrus.Logger) (*SlackAlertChannel, error) {
	slackConfig := &SlackConfig{}
	
	if enabled, ok := config["enabled"].(bool); ok {
		slackConfig.Enabled = enabled
	}
	if webhookURL, ok := config["webhook_url"].(string); ok {
		slackConfig.WebhookURL = webhookURL
	}
	if channel, ok := config["channel"].(string); ok {
		slackConfig.Channel = channel
	}
	if username, ok := config["username"].(string); ok {
		slackConfig.Username = username
	} else {
		slackConfig.Username = "AI Threat Detection"
	}
	if iconEmoji, ok := config["icon_emoji"].(string); ok {
		slackConfig.IconEmoji = iconEmoji
	} else {
		slackConfig.IconEmoji = ":warning:"
	}

	return &SlackAlertChannel{
		config: slackConfig,
		logger: logger,
	}, nil
}

// Send sends an alert to Slack
func (s *SlackAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !s.config.Enabled {
		return nil
	}

	message := s.formatSlackMessage(alert)
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack API returned status %d", resp.StatusCode)
	}

	s.logger.Infof("Slack alert sent for %s", alert.ID)
	return nil
}

// Name returns the channel name
func (s *SlackAlertChannel) Name() string {
	return "slack"
}

// HealthCheck checks if the Slack channel is healthy
func (s *SlackAlertChannel) HealthCheck() error {
	if !s.config.Enabled {
		return nil
	}
	
	if s.config.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL not configured")
	}
	
	return nil
}

// GetConfig returns the channel configuration
func (s *SlackAlertChannel) GetConfig() interface{} {
	return s.config
}

// SetConfig sets the channel configuration
func (s *SlackAlertChannel) SetConfig(config interface{}) error {
	if slackConfig, ok := config.(*SlackConfig); ok {
		s.config = slackConfig
		return nil
	}
	return fmt.Errorf("invalid config type for Slack channel")
}

func (s *SlackAlertChannel) formatSlackMessage(alert *Alert) *SlackMessage {
	color := s.getSeverityColor(alert.Severity)
	
	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("Alert: %s", alert.MetricName),
		Text:      alert.Message,
		Timestamp: alert.TriggeredAt.Unix(),
		Fields: []SlackField{
			{Title: "Severity", Value: string(alert.Severity), Short: true},
			{Title: "Status", Value: string(alert.Status), Short: true},
			{Title: "Alert ID", Value: alert.ID, Short: true},
		},
	}
	
	if alert.Threshold != nil {
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Current Value",
			Value: fmt.Sprintf("%.2f (threshold: %s %.2f)", 
				alert.CurrentValue, alert.Threshold.Operator, alert.Threshold.Value),
			Short: false,
		})
	}
	
	// Add labels as fields
	for k, v := range alert.Labels {
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: k,
			Value: v,
			Short: true,
		})
	}

	return &SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        fmt.Sprintf("AI Threat Detection Alert - %s", alert.Severity),
		Attachments: []SlackAttachment{attachment},
	}
}

func (s *SlackAlertChannel) getSeverityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityInfo:
		return "good"
	case AlertSeverityWarning:
		return "warning"
	case AlertSeverityError:
		return "danger"
	case AlertSeverityCritical:
		return "danger"
	default:
		return "warning"
	}
}

// NewWebhookAlertChannel creates a new webhook alert channel
func NewWebhookAlertChannel(config map[string]interface{}, logger *logrus.Logger) (*WebhookAlertChannel, error) {
	webhookConfig := &WebhookConfig{
		Method:     "POST",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		RetryDelay: 5 * time.Second,
		Headers:    make(map[string]string),
	}
	
	if enabled, ok := config["enabled"].(bool); ok {
		webhookConfig.Enabled = enabled
	}
	if url, ok := config["url"].(string); ok {
		webhookConfig.URL = url
	}
	if method, ok := config["method"].(string); ok {
		webhookConfig.Method = method
	}
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if headerValue, ok := v.(string); ok {
				webhookConfig.Headers[k] = headerValue
			}
		}
	}
	if timeout, ok := config["timeout"].(float64); ok {
		webhookConfig.Timeout = time.Duration(timeout) * time.Second
	}
	if retryCount, ok := config["retry_count"].(float64); ok {
		webhookConfig.RetryCount = int(retryCount)
	}
	if retryDelay, ok := config["retry_delay"].(float64); ok {
		webhookConfig.RetryDelay = time.Duration(retryDelay) * time.Second
	}

	// Set default headers
	if webhookConfig.Headers["Content-Type"] == "" {
		webhookConfig.Headers["Content-Type"] = "application/json"
	}

	return &WebhookAlertChannel{
		config: webhookConfig,
		client: &http.Client{Timeout: webhookConfig.Timeout},
		logger: logger,
	}, nil
}

// Send sends an alert to a webhook
func (w *WebhookAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !w.config.Enabled {
		return nil
	}

	jsonData, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= w.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.config.RetryDelay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, w.config.Method, w.config.URL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		// Set headers
		for k, v := range w.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to send webhook: %w", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.logger.Infof("Webhook alert sent for %s (attempt %d)", alert.ID, attempt+1)
			return nil
		}

		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook failed after %d attempts: %w", w.config.RetryCount+1, lastErr)
}

// Name returns the channel name
func (w *WebhookAlertChannel) Name() string {
	return "webhook"
}

// HealthCheck checks if the webhook channel is healthy
func (w *WebhookAlertChannel) HealthCheck() error {
	if !w.config.Enabled {
		return nil
	}
	
	if w.config.URL == "" {
		return fmt.Errorf("webhook URL not configured")
	}
	
	return nil
}

// GetConfig returns the channel configuration
func (w *WebhookAlertChannel) GetConfig() interface{} {
	return w.config
}

// SetConfig sets the channel configuration
func (w *WebhookAlertChannel) SetConfig(config interface{}) error {
	if webhookConfig, ok := config.(*WebhookConfig); ok {
		w.config = webhookConfig
		w.client.Timeout = webhookConfig.Timeout
		return nil
	}
	return fmt.Errorf("invalid config type for webhook channel")
}

// NewPagerDutyAlertChannel creates a new PagerDuty alert channel
func NewPagerDutyAlertChannel(config map[string]interface{}, logger *logrus.Logger) (*PagerDutyAlertChannel, error) {
	pagerDutyConfig := &PagerDutyConfig{
		Severity:  "error",
		Source:    "ai-threat-detection",
		Component: "threat-detector",
	}
	
	if enabled, ok := config["enabled"].(bool); ok {
		pagerDutyConfig.Enabled = enabled
	}
	if integrationKey, ok := config["integration_key"].(string); ok {
		pagerDutyConfig.IntegrationKey = integrationKey
	}
	if severity, ok := config["severity"].(string); ok {
		pagerDutyConfig.Severity = severity
	}
	if source, ok := config["source"].(string); ok {
		pagerDutyConfig.Source = source
	}
	if component, ok := config["component"].(string); ok {
		pagerDutyConfig.Component = component
	}
	if group, ok := config["group"].(string); ok {
		pagerDutyConfig.Group = group
	}
	if class, ok := config["class"].(string); ok {
		pagerDutyConfig.Class = class
	}

	return &PagerDutyAlertChannel{
		config: pagerDutyConfig,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
	}, nil
}

// Send sends an alert to PagerDuty
func (p *PagerDutyAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !p.config.Enabled {
		return nil
	}

	event := p.formatPagerDutyEvent(alert)
	
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal PagerDuty event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send PagerDuty event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("PagerDuty API returned status %d", resp.StatusCode)
	}

	p.logger.Infof("PagerDuty alert sent for %s", alert.ID)
	return nil
}

// Name returns the channel name
func (p *PagerDutyAlertChannel) Name() string {
	return "pagerduty"
}

// HealthCheck checks if the PagerDuty channel is healthy
func (p *PagerDutyAlertChannel) HealthCheck() error {
	if !p.config.Enabled {
		return nil
	}
	
	if p.config.IntegrationKey == "" {
		return fmt.Errorf("PagerDuty integration key not configured")
	}
	
	return nil
}

// GetConfig returns the channel configuration
func (p *PagerDutyAlertChannel) GetConfig() interface{} {
	return p.config
}

// SetConfig sets the channel configuration
func (p *PagerDutyAlertChannel) SetConfig(config interface{}) error {
	if pagerDutyConfig, ok := config.(*PagerDutyConfig); ok {
		p.config = pagerDutyConfig
		return nil
	}
	return fmt.Errorf("invalid config type for PagerDuty channel")
}

func (p *PagerDutyAlertChannel) formatPagerDutyEvent(alert *Alert) *PagerDutyEvent {
	severity := p.mapSeverity(alert.Severity)
	
	customDetails := make(map[string]interface{})
	customDetails["alert_id"] = alert.ID
	customDetails["metric_name"] = alert.MetricName
	customDetails["triggered_at"] = alert.TriggeredAt.Format(time.RFC3339)
	
	if alert.Threshold != nil {
		customDetails["threshold"] = fmt.Sprintf("%s %s %.2f", 
			alert.Threshold.MetricName, alert.Threshold.Operator, alert.Threshold.Value)
		customDetails["current_value"] = alert.CurrentValue
	}
	
	// Add labels and metadata
	for k, v := range alert.Labels {
		customDetails["label_"+k] = v
	}
	for k, v := range alert.Metadata {
		customDetails["metadata_"+k] = v
	}

	return &PagerDutyEvent{
		RoutingKey:  p.config.IntegrationKey,
		EventAction: "trigger",
		DedupKey:    alert.ID,
		Payload: PagerDutyEventPayload{
			Summary:       alert.Message,
			Source:        p.config.Source,
			Severity:      severity,
			Timestamp:     alert.TriggeredAt.Format(time.RFC3339),
			Component:     p.config.Component,
			Group:         p.config.Group,
			Class:         p.config.Class,
			CustomDetails: customDetails,
		},
	}
}

func (p *PagerDutyAlertChannel) mapSeverity(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityInfo:
		return "info"
	case AlertSeverityWarning:
		return "warning"
	case AlertSeverityError:
		return "error"
	case AlertSeverityCritical:
		return "critical"
	default:
		return "error"
	}
}
type WebhookAlertChannel struct {
	config *WebhookConfig
	logger *logrus.Logger
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	Enabled     bool              `json:"enabled"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	RetryDelay  time.Duration     `json:"retry_delay"`
}

// PagerDutyAlertChannel sends alerts to PagerDuty
type PagerDutyAlertChannel struct {
	config *PagerDutyConfig
	logger *logrus.Logger
}

// PagerDutyConfig holds PagerDuty configuration
type PagerDutyConfig struct {
	Enabled        bool   `json:"enabled"`
	IntegrationKey string `json:"integration_key"`
	ServiceURL     string `json:"service_url"`
}

// TeamsAlertChannel sends alerts to Microsoft Teams
type TeamsAlertChannel struct {
	config *TeamsConfig
	logger *logrus.Logger
}

// TeamsConfig holds Microsoft Teams configuration
type TeamsConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
}

// DiscordAlertChannel sends alerts to Discord
type DiscordAlertChannel struct {
	config *DiscordConfig
	logger *logrus.Logger
}

// DiscordConfig holds Discord configuration
type DiscordConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Username   string `json:"username"`
	AvatarURL  string `json:"avatar_url"`
}

// Slack message structures
type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Color      string       `json:"color"`
	Title      string       `json:"title"`
	Text       string       `json:"text"`
	Fields     []SlackField `json:"fields,omitempty"`
	Timestamp  int64        `json:"ts"`
	Footer     string       `json:"footer,omitempty"`
	FooterIcon string       `json:"footer_icon,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// Teams message structures
type TeamsMessage struct {
	Type       string                `json:"@type"`
	Context    string                `json:"@context"`
	Summary    string                `json:"summary"`
	Title      string                `json:"title"`
	Text       string                `json:"text"`
	ThemeColor string                `json:"themeColor"`
	Sections   []TeamsMessageSection `json:"sections,omitempty"`
}

type TeamsMessageSection struct {
	ActivityTitle    string            `json:"activityTitle,omitempty"`
	ActivitySubtitle string            `json:"activitySubtitle,omitempty"`
	ActivityImage    string            `json:"activityImage,omitempty"`
	Facts            []TeamsMessageFact `json:"facts,omitempty"`
	Text             string            `json:"text,omitempty"`
}

type TeamsMessageFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Discord message structures
type DiscordMessage struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Content   string         `json:"content"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp"`
}

type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordEmbedFooter struct {
	Text    string `json:"text"`
	IconURL string `json:"icon_url,omitempty"`
}

// PagerDuty event structures
type PagerDutyEvent struct {
	RoutingKey  string                 `json:"routing_key"`
	EventAction string                 `json:"event_action"`
	DedupKey    string                 `json:"dedup_key,omitempty"`
	Payload     PagerDutyEventPayload  `json:"payload"`
	Client      string                 `json:"client,omitempty"`
	ClientURL   string                 `json:"client_url,omitempty"`
}

type PagerDutyEventPayload struct {
	Summary       string                 `json:"summary"`
	Source        string                 `json:"source"`
	Severity      string                 `json:"severity"`
	Timestamp     string                 `json:"timestamp,omitempty"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

// EmailAlertChannel implementation

func NewEmailAlertChannel(config *EmailConfig, logger *logrus.Logger) *EmailAlertChannel {
	return &EmailAlertChannel{
		config: config,
		logger: logger,
	}
}

func (e *EmailAlertChannel) Name() string {
	return "email"
}

func (e *EmailAlertChannel) IsEnabled() bool {
	return e.config.Enabled
}

func (e *EmailAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !e.config.Enabled {
		return fmt.Errorf("email alerts are disabled")
	}
	
	subject := e.config.Subject
	if subject == "" {
		subject = fmt.Sprintf("[AI Security Alert] %s", alert.Title)
	}
	
	body := e.formatEmailBody(alert)
	
	// Create email message
	msg := fmt.Sprintf("From: %s\r\n", e.config.From)
	msg += fmt.Sprintf("To: %s\r\n", strings.Join(e.config.Recipients, ","))
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "Content-Type: text/html; charset=UTF-8\r\n"
	msg += "\r\n"
	msg += body
	
	// Send email
	auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)
	
	err := smtp.SendMail(addr, auth, e.config.From, e.config.Recipients, []byte(msg))
	if err != nil {
		e.logger.Errorf("Failed to send email alert: %v", err)
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	e.logger.Infof("Email alert sent successfully to %d recipients", len(e.config.Recipients))
	return nil
}

func (e *EmailAlertChannel) formatEmailBody(alert *Alert) string {
	severityColor := e.getSeverityColor(alert.Severity)
	
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI Security Alert</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert-header { background-color: %s; color: white; padding: 15px; border-radius: 5px; }
        .alert-body { padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }
        .metadata { background-color: #f5f5f5; padding: 10px; border-radius: 3px; margin-top: 10px; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="alert-header">
        <h2>🚨 %s</h2>
        <p><strong>Severity:</strong> %s | <strong>Component:</strong> %s</p>
    </div>
    <div class="alert-body">
        <p><strong>Description:</strong></p>
        <p>%s</p>
        <div class="metadata">
            <p><strong>Alert ID:</strong> %s</p>
            <p><strong>Type:</strong> %s</p>
            <p class="timestamp"><strong>Timestamp:</strong> %s</p>
        </div>
    </div>
</body>
</html>`,
		severityColor,
		alert.Title,
		alert.Severity,
		alert.Component,
		alert.Description,
		alert.ID,
		alert.Type,
		alert.Timestamp.Format("2006-01-02 15:04:05 UTC"),
	)
	
	return html
}

func (e *EmailAlertChannel) getSeverityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "#dc3545"
	case AlertSeverityError:
		return "#fd7e14"
	case AlertSeverityWarning:
		return "#ffc107"
	case AlertSeverityInfo:
		return "#17a2b8"
	default:
		return "#6c757d"
	}
}

// SlackAlertChannel implementation

func NewSlackAlertChannel(config *SlackConfig, logger *logrus.Logger) *SlackAlertChannel {
	return &SlackAlertChannel{
		config: config,
		logger: logger,
	}
}

func (s *SlackAlertChannel) Name() string {
	return "slack"
}

func (s *SlackAlertChannel) IsEnabled() bool {
	return s.config.Enabled && s.config.WebhookURL != ""
}

func (s *SlackAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !s.IsEnabled() {
		return fmt.Errorf("slack alerts are disabled or not configured")
	}
	
	message := s.formatSlackMessage(alert)
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack message: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}
	
	s.logger.Info("Slack alert sent successfully")
	return nil
}

func (s *SlackAlertChannel) formatSlackMessage(alert *Alert) *SlackMessage {
	color := s.getSeverityColor(alert.Severity)
	emoji := s.getSeverityEmoji(alert.Severity)
	
	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("%s %s", emoji, alert.Title),
		Text:      alert.Description,
		Timestamp: alert.Timestamp.Unix(),
		Footer:    "AI Security System",
		Fields: []SlackField{
			{
				Title: "Component",
				Value: alert.Component,
				Short: true,
			},
			{
				Title: "Severity",
				Value: string(alert.Severity),
				Short: true,
			},
			{
				Title: "Alert Type",
				Value: string(alert.Type),
				Short: true,
			},
			{
				Title: "Alert ID",
				Value: alert.ID,
				Short: true,
			},
		},
	}
	
	message := &SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        fmt.Sprintf("AI Security Alert: %s", alert.Title),
		Attachments: []SlackAttachment{attachment},
	}
	
	return message
}

func (s *SlackAlertChannel) getSeverityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "danger"
	case AlertSeverityError:
		return "warning"
	case AlertSeverityWarning:
		return "warning"
	case AlertSeverityInfo:
		return "good"
	default:
		return "#808080"
	}
}

func (s *SlackAlertChannel) getSeverityEmoji(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "🚨"
	case AlertSeverityError:
		return "❌"
	case AlertSeverityWarning:
		return "⚠️"
	case AlertSeverityInfo:
		return "ℹ️"
	default:
		return "📢"
	}
}

// WebhookAlertChannel implementation

func NewWebhookAlertChannel(config *WebhookConfig, logger *logrus.Logger) *WebhookAlertChannel {
	return &WebhookAlertChannel{
		config: config,
		logger: logger,
	}
}

func (w *WebhookAlertChannel) Name() string {
	return "webhook"
}

func (w *WebhookAlertChannel) IsEnabled() bool {
	return w.config.Enabled && w.config.URL != ""
}

func (w *WebhookAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !w.IsEnabled() {
		return fmt.Errorf("webhook alerts are disabled or not configured")
	}
	
	payload := map[string]interface{}{
		"alert_id":    alert.ID,
		"type":        alert.Type,
		"severity":    alert.Severity,
		"component":   alert.Component,
		"title":       alert.Title,
		"description": alert.Description,
		"timestamp":   alert.Timestamp.Format(time.RFC3339),
		"metadata":    alert.Metadata,
		"escalated":   alert.Escalated,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}
	
	method := w.config.Method
	if method == "" {
		method = "POST"
	}
	
	var lastErr error
	for attempt := 0; attempt <= w.config.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(w.config.RetryDelay)
			w.logger.Infof("Retrying webhook alert (attempt %d/%d)", attempt+1, w.config.RetryCount+1)
		}
		
		req, err := http.NewRequestWithContext(ctx, method, w.config.URL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AI-Security-System/1.0")
		
		// Add custom headers
		for key, value := range w.config.Headers {
			req.Header.Set(key, value)
		}
		
		timeout := w.config.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to send webhook: %w", err)
			continue
		}
		
		resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.logger.Info("Webhook alert sent successfully")
			return nil
		}
		
		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	
	return fmt.Errorf("webhook failed after %d attempts: %w", w.config.RetryCount+1, lastErr)
}

// PagerDutyAlertChannel implementation

func NewPagerDutyAlertChannel(config *PagerDutyConfig, logger *logrus.Logger) *PagerDutyAlertChannel {
	return &PagerDutyAlertChannel{
		config: config,
		logger: logger,
	}
}

func (p *PagerDutyAlertChannel) Name() string {
	return "pagerduty"
}

func (p *PagerDutyAlertChannel) IsEnabled() bool {
	return p.config.Enabled && p.config.IntegrationKey != ""
}

func (p *PagerDutyAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !p.IsEnabled() {
		return fmt.Errorf("pagerduty alerts are disabled or not configured")
	}
	
	event := PagerDutyEvent{
		RoutingKey:  p.config.IntegrationKey,
		EventAction: "trigger",
		DedupKey:    alert.ID,
		Client:      "AI Security System",
		ClientURL:   p.config.ServiceURL,
		Payload: PagerDutyEventPayload{
			Summary:   alert.Title,
			Source:    "ai-security-system",
			Severity:  p.mapSeverity(alert.Severity),
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
	
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty event: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send pagerduty event: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty API returned status %d", resp.StatusCode)
	}
	
	p.logger.Info("PagerDuty alert sent successfully")
	return nil
}

func (p *PagerDutyAlertChannel) mapSeverity(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "critical"
	case AlertSeverityError:
		return "error"
	case AlertSeverityWarning:
		return "warning"
	case AlertSeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// TeamsAlertChannel implementation

func NewTeamsAlertChannel(config *TeamsConfig, logger *logrus.Logger) *TeamsAlertChannel {
	return &TeamsAlertChannel{
		config: config,
		logger: logger,
	}
}

func (t *TeamsAlertChannel) Name() string {
	return "teams"
}

func (t *TeamsAlertChannel) IsEnabled() bool {
	return t.config.Enabled && t.config.WebhookURL != ""
}

func (t *TeamsAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !t.IsEnabled() {
		return fmt.Errorf("teams alerts are disabled or not configured")
	}
	
	message := t.formatTeamsMessage(alert)
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal teams message: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", t.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send teams message: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("teams webhook returned status %d", resp.StatusCode)
	}
	
	t.logger.Info("Teams alert sent successfully")
	return nil
}

func (t *TeamsAlertChannel) formatTeamsMessage(alert *Alert) *TeamsMessage {
	themeColor := t.getSeverityColor(alert.Severity)
	
	facts := []TeamsMessageFact{
		{Name: "Component", Value: alert.Component},
		{Name: "Severity", Value: string(alert.Severity)},
		{Name: "Alert Type", Value: string(alert.Type)},
		{Name: "Alert ID", Value: alert.ID},
		{Name: "Timestamp", Value: alert.Timestamp.Format("2006-01-02 15:04:05 UTC")},
	}
	
	message := &TeamsMessage{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		Summary:    alert.Title,
		Title:      "🚨 AI Security Alert",
		Text:       alert.Description,
		ThemeColor: themeColor,
		Sections: []TeamsMessageSection{
			{
				ActivityTitle:    alert.Title,
				ActivitySubtitle: fmt.Sprintf("Severity: %s | Component: %s", alert.Severity, alert.Component),
				Facts:            facts,
			},
		},
	}
	
	return message
}

func (t *TeamsAlertChannel) getSeverityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "FF0000"
	case AlertSeverityError:
		return "FF8C00"
	case AlertSeverityWarning:
		return "FFD700"
	case AlertSeverityInfo:
		return "0078D4"
	default:
		return "808080"
	}
}

// DiscordAlertChannel implementation

func NewDiscordAlertChannel(config *DiscordConfig, logger *logrus.Logger) *DiscordAlertChannel {
	return &DiscordAlertChannel{
		config: config,
		logger: logger,
	}
}

func (d *DiscordAlertChannel) Name() string {
	return "discord"
}

func (d *DiscordAlertChannel) IsEnabled() bool {
	return d.config.Enabled && d.config.WebhookURL != ""
}

func (d *DiscordAlertChannel) Send(ctx context.Context, alert *Alert) error {
	if !d.IsEnabled() {
		return fmt.Errorf("discord alerts are disabled or not configured")
	}
	
	message := d.formatDiscordMessage(alert)
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal discord message: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", d.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send discord message: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}
	
	d.logger.Info("Discord alert sent successfully")
	return nil
}

func (d *DiscordAlertChannel) formatDiscordMessage(alert *Alert) *DiscordMessage {
	color := d.getSeverityColor(alert.Severity)
	
	fields := []DiscordEmbedField{
		{Name: "Component", Value: alert.Component, Inline: true},
		{Name: "Severity", Value: string(alert.Severity), Inline: true},
		{Name: "Alert Type", Value: string(alert.Type), Inline: true},
		{Name: "Alert ID", Value: alert.ID, Inline: false},
	}
	
	embed := DiscordEmbed{
		Title:       alert.Title,
		Description: alert.Description,
		Color:       color,
		Fields:      fields,
		Footer: &DiscordEmbedFooter{
			Text: "AI Security System",
		},
		Timestamp: alert.Timestamp.Format(time.RFC3339),
	}
	
	message := &DiscordMessage{
		Username:  d.config.Username,
		AvatarURL: d.config.AvatarURL,
		Content:   "🚨 **AI Security Alert**",
		Embeds:    []DiscordEmbed{embed},
	}
	
	return message
}

func (d *DiscordAlertChannel) getSeverityColor(severity AlertSeverity) int {
	switch severity {
	case AlertSeverityCritical:
		return 0xFF0000 // Red
	case AlertSeverityError:
		return 0xFF8C00 // Dark Orange
	case AlertSeverityWarning:
		return 0xFFD700 // Gold
	case AlertSeverityInfo:
		return 0x0078D4 // Blue
	default:
		return 0x808080 // Gray
	}
}