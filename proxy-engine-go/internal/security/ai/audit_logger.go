package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AuditLogger provides comprehensive logging and audit trail for AI threat detection
type AuditLogger struct {
	logger          *logrus.Logger
	storage         AuditStorage
	config          *AuditConfig
	stats           *AuditStats
	eventBuffer     []*AuditEvent
	retentionPolicy *RetentionPolicy
	mu              sync.RWMutex
}

// AuditStorage defines interface for audit log persistence
type AuditStorage interface {
	SaveAuditEvent(ctx context.Context, event *AuditEvent) error
	LoadAuditEvents(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditEvent, error)
	DeleteAuditEvents(ctx context.Context, filter *AuditFilter) (int64, error)
	GetAuditStats(ctx context.Context, timeRange TimeRange) (*AuditStorageStats, error)
	ArchiveAuditEvents(ctx context.Context, beforeTime time.Time) (int64, error)
	CleanupExpiredEvents(ctx context.Context) (int64, error)
}

// AuditConfig holds configuration for audit logging
type AuditConfig struct {
	Enabled                bool          `json:"enabled"`
	LogLevel               logrus.Level  `json:"log_level"`
	EnableStructuredLogs   bool          `json:"enable_structured_logs"`
	EnableFileOutput       bool          `json:"enable_file_output"`
	EnableDatabaseStorage  bool          `json:"enable_database_storage"`
	EnableRealTimeAlerts   bool          `json:"enable_real_time_alerts"`
	BufferSize             int           `json:"buffer_size"`
	FlushInterval          time.Duration `json:"flush_interval"`
	MaxEventSize           int           `json:"max_event_size"`
	IncludeSensitiveData   bool          `json:"include_sensitive_data"`
	MaskSensitiveFields    bool          `json:"mask_sensitive_fields"`
	CompressLogs           bool          `json:"compress_logs"`
	EncryptLogs            bool          `json:"encrypt_logs"`
	LogRotationSize        int64         `json:"log_rotation_size"`
	LogRetentionDays       int           `json:"log_retention_days"`
	AlertThresholds        map[string]int64 `json:"alert_thresholds"`
}

// AuditStats tracks audit logging statistics
type AuditStats struct {
	TotalEvents           int64                    `json:"total_events"`
	EventsByType          map[AuditEventType]int64 `json:"events_by_type"`
	EventsBySeverity      map[AuditSeverity]int64  `json:"events_by_severity"`
	EventsByAction        map[AuditAction]int64    `json:"events_by_action"`
	EventsBySource        map[string]int64         `json:"events_by_source"`
	EventsBuffered        int64                    `json:"events_buffered"`
	EventsFlushed         int64                    `json:"events_flushed"`
	EventsDropped         int64                    `json:"events_dropped"`
	StorageErrors         int64                    `json:"storage_errors"`
	AverageEventSize      int64                    `json:"average_event_size"`
	LastFlush             time.Time                `json:"last_flush"`
	LastUpdated           time.Time                `json:"last_updated"`
}

// AuditEvent represents a comprehensive audit log entry
type AuditEvent struct {
	ID                string                 `json:"id"`
	Timestamp         time.Time              `json:"timestamp"`
	Type              AuditEventType         `json:"type"`
	Severity          AuditSeverity          `json:"severity"`
	Action            AuditAction            `json:"action"`
	Source            string                 `json:"source"`
	Component         string                 `json:"component"`
	UserID            string                 `json:"user_id,omitempty"`
	SessionID         string                 `json:"session_id,omitempty"`
	RequestID         string                 `json:"request_id,omitempty"`
	ClientIP          string                 `json:"client_ip,omitempty"`
	UserAgent         string                 `json:"user_agent,omitempty"`
	URL               string                 `json:"url,omitempty"`
	Method            string                 `json:"method,omitempty"`
	StatusCode        int                    `json:"status_code,omitempty"`
	ResponseTime      time.Duration          `json:"response_time,omitempty"`
	ThreatAnalysis    *ThreatAnalysisResult  `json:"threat_analysis,omitempty"`
	BehaviorAnalysis  *BehaviorAnalysis      `json:"behavior_analysis,omitempty"`
	RateLimitResult   *AdaptiveRateLimitResult `json:"rate_limit_result,omitempty"`
	ModelInfo         *ModelAuditInfo        `json:"model_info,omitempty"`
	ConfigChanges     map[string]interface{} `json:"config_changes,omitempty"`
	ErrorDetails      *ErrorDetails          `json:"error_details,omitempty"`
	SecurityContext   *SecurityContext       `json:"security_context,omitempty"`
	ComplianceInfo    *ComplianceInfo        `json:"compliance_info,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Hash              string                 `json:"hash,omitempty"`
	Signature         string                 `json:"signature,omitempty"`
}

// AuditEventType defines types of audit events
type AuditEventType string

const (
	AuditEventThreatDetection    AuditEventType = "threat_detection"
	AuditEventBehaviorAnalysis   AuditEventType = "behavior_analysis"
	AuditEventRateLimit          AuditEventType = "rate_limit"
	AuditEventModelUpdate        AuditEventType = "model_update"
	AuditEventConfigChange       AuditEventType = "config_change"
	AuditEventUserAction         AuditEventType = "user_action"
	AuditEventSystemEvent        AuditEventType = "system_event"
	AuditEventSecurityIncident   AuditEventType = "security_incident"
	AuditEventComplianceCheck    AuditEventType = "compliance_check"
	AuditEventDataAccess         AuditEventType = "data_access"
	AuditEventAuthentication     AuditEventType = "authentication"
	AuditEventAuthorization      AuditEventType = "authorization"
	AuditEventError              AuditEventType = "error"
)

// AuditSeverity defines severity levels for audit events
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditAction defines specific actions being audited
type AuditAction string

const (
	AuditActionAnalyze       AuditAction = "analyze"
	AuditActionBlock         AuditAction = "block"
	AuditActionAllow         AuditAction = "allow"
	AuditActionChallenge     AuditAction = "challenge"
	AuditActionRateLimit     AuditAction = "rate_limit"
	AuditActionTrain         AuditAction = "train"
	AuditActionUpdate        AuditAction = "update"
	AuditActionDelete        AuditAction = "delete"
	AuditActionCreate        AuditAction = "create"
	AuditActionRead          AuditAction = "read"
	AuditActionLogin         AuditAction = "login"
	AuditActionLogout        AuditAction = "logout"
	AuditActionConfigChange  AuditAction = "config_change"
	AuditActionEmergencyMode AuditAction = "emergency_mode"
)

// Supporting types

type ModelAuditInfo struct {
	ModelName       string            `json:"model_name"`
	ModelVersion    string            `json:"model_version"`
	TrainingSize    int               `json:"training_size,omitempty"`
	Accuracy        float64           `json:"accuracy,omitempty"`
	PerformanceMetrics map[string]float64 `json:"performance_metrics,omitempty"`
	TrainingDuration time.Duration    `json:"training_duration,omitempty"`
}

type ErrorDetails struct {
	ErrorType    string `json:"error_type"`
	ErrorMessage string `json:"error_message"`
	StackTrace   string `json:"stack_trace,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

type SecurityContext struct {
	AuthenticationMethod string            `json:"authentication_method,omitempty"`
	AuthorizationLevel   string            `json:"authorization_level,omitempty"`
	Permissions          []string          `json:"permissions,omitempty"`
	SecurityHeaders      map[string]string `json:"security_headers,omitempty"`
	TLSVersion           string            `json:"tls_version,omitempty"`
	CertificateInfo      string            `json:"certificate_info,omitempty"`
}

type ComplianceInfo struct {
	Regulation     string            `json:"regulation"`
	ComplianceLevel string           `json:"compliance_level"`
	RequiredFields []string          `json:"required_fields"`
	DataClassification string        `json:"data_classification"`
	RetentionPeriod time.Duration    `json:"retention_period"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type AuditFilter struct {
	StartTime    time.Time         `json:"start_time,omitempty"`
	EndTime      time.Time         `json:"end_time,omitempty"`
	EventTypes   []AuditEventType  `json:"event_types,omitempty"`
	Severities   []AuditSeverity   `json:"severities,omitempty"`
	Actions      []AuditAction     `json:"actions,omitempty"`
	Sources      []string          `json:"sources,omitempty"`
	Components   []string          `json:"components,omitempty"`
	UserIDs      []string          `json:"user_ids,omitempty"`
	ClientIPs    []string          `json:"client_ips,omitempty"`
	RequestIDs   []string          `json:"request_ids,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	SearchText   string            `json:"search_text,omitempty"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type RetentionPolicy struct {
	DefaultRetention    time.Duration            `json:"default_retention"`
	RetentionByType     map[AuditEventType]time.Duration `json:"retention_by_type"`
	RetentionBySeverity map[AuditSeverity]time.Duration  `json:"retention_by_severity"`
	ArchiveAfter        time.Duration            `json:"archive_after"`
	DeleteAfter         time.Duration            `json:"delete_after"`
	CompressAfter       time.Duration            `json:"compress_after"`
}

type AuditStorageStats struct {
	TotalEvents      int64     `json:"total_events"`
	StorageSize      int64     `json:"storage_size_bytes"`
	OldestEvent      time.Time `json:"oldest_event"`
	NewestEvent      time.Time `json:"newest_event"`
	EventsArchived   int64     `json:"events_archived"`
	EventsDeleted    int64     `json:"events_deleted"`
	CompressionRatio float64   `json:"compression_ratio"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *logrus.Logger, storage AuditStorage) *AuditLogger {
	return &AuditLogger{
		logger:          logger,
		storage:         storage,
		config:          getDefaultAuditConfig(),
		stats:           getDefaultAuditStats(),
		eventBuffer:     make([]*AuditEvent, 0),
		retentionPolicy: getDefaultRetentionPolicy(),
	}
}

// LogThreatDetection logs a threat detection event
func (al *AuditLogger) LogThreatDetection(ctx context.Context, request *ThreatAnalysisRequest, result *ThreatAnalysisResult, responseTime time.Duration) {
	if !al.config.Enabled {
		return
	}
	
	event := &AuditEvent{
		ID:               generateAuditEventID(),
		Timestamp:        time.Now(),
		Type:             AuditEventThreatDetection,
		Severity:         al.mapThreatLevelToSeverity(result.ThreatLevel),
		Action:           AuditActionAnalyze,
		Source:           "ai_threat_detector",
		Component:        "threat_detection",
		UserID:           request.UserID,
		SessionID:        request.SessionID,
		RequestID:        request.RequestID,
		ClientIP:         request.ClientIP,
		UserAgent:        request.UserAgent,
		URL:              request.URL,
		Method:           request.Method,
		ResponseTime:     responseTime,
		ThreatAnalysis:   result,
		Tags:             al.generateThreatTags(result),
		Metadata: map[string]interface{}{
			"request_size": len(request.Body),
			"features_extracted": len(result.MLPredictions),
		},
	}
	
	if result.IsThreat {
		event.SecurityContext = &SecurityContext{
			SecurityHeaders: request.Headers,
		}
		event.ComplianceInfo = &ComplianceInfo{
			Regulation:         "GDPR",
			DataClassification: "sensitive",
			RetentionPeriod:    al.retentionPolicy.RetentionByType[AuditEventThreatDetection],
		}
	}
	
	al.logEvent(ctx, event)
}

// LogBehaviorAnalysis logs a behavioral analysis event
func (al *AuditLogger) LogBehaviorAnalysis(ctx context.Context, subject string, analysis *BehaviorAnalysis) {
	if !al.config.Enabled {
		return
	}
	
	severity := AuditSeverityInfo
	if analysis.IsAnomalous {
		if analysis.AnomalyScore >= 0.8 {
			severity = AuditSeverityCritical
		} else if analysis.AnomalyScore >= 0.6 {
			severity = AuditSeverityError
		} else {
			severity = AuditSeverityWarning
		}
	}
	
	event := &AuditEvent{
		ID:               generateAuditEventID(),
		Timestamp:        time.Now(),
		Type:             AuditEventBehaviorAnalysis,
		Severity:         severity,
		Action:           AuditActionAnalyze,
		Source:           "behavioral_analyzer",
		Component:        "behavior_analysis",
		BehaviorAnalysis: analysis,
		Tags:             []string{"behavior", "analysis", subject},
		Metadata: map[string]interface{}{
			"subject":       subject,
			"anomaly_score": analysis.AnomalyScore,
			"is_anomalous":  analysis.IsAnomalous,
		},
	}
	
	al.logEvent(ctx, event)
}

// LogRateLimit logs a rate limiting event
func (al *AuditLogger) LogRateLimit(ctx context.Context, request *AdaptiveRateLimitRequest, result *AdaptiveRateLimitResult) {
	if !al.config.Enabled {
		return
	}
	
	severity := AuditSeverityInfo
	action := AuditActionAllow
	
	if !result.Allowed {
		severity = AuditSeverityWarning
		action = AuditActionRateLimit
	}
	
	event := &AuditEvent{
		ID:              generateAuditEventID(),
		Timestamp:       time.Now(),
		Type:            AuditEventRateLimit,
		Severity:        severity,
		Action:          action,
		Source:          "adaptive_rate_limiter",
		Component:       "rate_limiting",
		UserID:          request.UserID,
		ClientIP:        request.IP,
		RateLimitResult: result,
		Tags:            []string{"rate_limit", string(action)},
		Metadata: map[string]interface{}{
			"multiplier":        result.AppliedMultiplier,
			"adjustment_reason": result.AdjustmentReason,
			"emergency_mode":    result.EmergencyMode,
		},
	}
	
	al.logEvent(ctx, event)
}

// LogModelUpdate logs a model update event
func (al *AuditLogger) LogModelUpdate(ctx context.Context, modelName, version string, trainingSize int, metrics map[string]float64, duration time.Duration) {
	if !al.config.Enabled {
		return
	}
	
	event := &AuditEvent{
		ID:        generateAuditEventID(),
		Timestamp: time.Now(),
		Type:      AuditEventModelUpdate,
		Severity:  AuditSeverityInfo,
		Action:    AuditActionUpdate,
		Source:    "model_manager",
		Component: "machine_learning",
		ModelInfo: &ModelAuditInfo{
			ModelName:          modelName,
			ModelVersion:       version,
			TrainingSize:       trainingSize,
			PerformanceMetrics: metrics,
			TrainingDuration:   duration,
		},
		Tags: []string{"model", "training", modelName},
		Metadata: map[string]interface{}{
			"training_duration_seconds": duration.Seconds(),
			"training_size":             trainingSize,
		},
	}
	
	if accuracy, exists := metrics["accuracy"]; exists {
		event.ModelInfo.Accuracy = accuracy
	}
	
	al.logEvent(ctx, event)
}

// LogConfigChange logs a configuration change event
func (al *AuditLogger) LogConfigChange(ctx context.Context, component, userID string, changes map[string]interface{}) {
	if !al.config.Enabled {
		return
	}
	
	event := &AuditEvent{
		ID:            generateAuditEventID(),
		Timestamp:     time.Now(),
		Type:          AuditEventConfigChange,
		Severity:      AuditSeverityWarning,
		Action:        AuditActionConfigChange,
		Source:        "configuration_manager",
		Component:     component,
		UserID:        userID,
		ConfigChanges: changes,
		Tags:          []string{"config", "change", component},
		Metadata: map[string]interface{}{
			"changes_count": len(changes),
		},
		ComplianceInfo: &ComplianceInfo{
			Regulation:      "SOX",
			ComplianceLevel: "high",
			RequiredFields:  []string{"user_id", "timestamp", "changes"},
			RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years for SOX
		},
	}
	
	al.logEvent(ctx, event)
}

// LogSecurityIncident logs a security incident
func (al *AuditLogger) LogSecurityIncident(ctx context.Context, incidentType, description string, severity AuditSeverity, context map[string]interface{}) {
	if !al.config.Enabled {
		return
	}
	
	event := &AuditEvent{
		ID:        generateAuditEventID(),
		Timestamp: time.Now(),
		Type:      AuditEventSecurityIncident,
		Severity:  severity,
		Action:    AuditActionBlock,
		Source:    "security_monitor",
		Component: "incident_response",
		Tags:      []string{"security", "incident", incidentType},
		Metadata: map[string]interface{}{
			"incident_type": incidentType,
			"description":   description,
			"context":       context,
		},
		ComplianceInfo: &ComplianceInfo{
			Regulation:         "PCI-DSS",
			ComplianceLevel:    "critical",
			DataClassification: "confidential",
			RetentionPeriod:    3 * 365 * 24 * time.Hour, // 3 years for PCI-DSS
		},
	}
	
	al.logEvent(ctx, event)
}

// LogError logs an error event
func (al *AuditLogger) LogError(ctx context.Context, component, errorType, errorMessage string, err error) {
	if !al.config.Enabled {
		return
	}
	
	event := &AuditEvent{
		ID:        generateAuditEventID(),
		Timestamp: time.Now(),
		Type:      AuditEventError,
		Severity:  AuditSeverityError,
		Action:    AuditActionRead, // Error occurred during some operation
		Source:    "error_handler",
		Component: component,
		ErrorDetails: &ErrorDetails{
			ErrorType:    errorType,
			ErrorMessage: errorMessage,
		},
		Tags: []string{"error", component, errorType},
		Metadata: map[string]interface{}{
			"error_occurred": true,
		},
	}
	
	if err != nil {
		event.ErrorDetails.StackTrace = fmt.Sprintf("%+v", err)
	}
	
	al.logEvent(ctx, event)
}

// LogUserAction logs a user action
func (al *AuditLogger) LogUserAction(ctx context.Context, userID, action, resource string, success bool, clientIP string) {
	if !al.config.Enabled {
		return
	}
	
	severity := AuditSeverityInfo
	if !success {
		severity = AuditSeverityWarning
	}
	
	event := &AuditEvent{
		ID:        generateAuditEventID(),
		Timestamp: time.Now(),
		Type:      AuditEventUserAction,
		Severity:  severity,
		Action:    AuditAction(action),
		Source:    "user_interface",
		Component: "user_management",
		UserID:    userID,
		ClientIP:  clientIP,
		Tags:      []string{"user", "action", action},
		Metadata: map[string]interface{}{
			"resource": resource,
			"success":  success,
		},
		ComplianceInfo: &ComplianceInfo{
			Regulation:      "GDPR",
			ComplianceLevel: "medium",
			RequiredFields:  []string{"user_id", "action", "timestamp"},
			RetentionPeriod: 2 * 365 * 24 * time.Hour, // 2 years for GDPR
		},
	}
	
	al.logEvent(ctx, event)
}

// Private methods

func (al *AuditLogger) logEvent(ctx context.Context, event *AuditEvent) {
	// Add hash for integrity
	event.Hash = al.calculateEventHash(event)
	
	// Mask sensitive data if configured
	if al.config.MaskSensitiveFields {
		al.maskSensitiveData(event)
	}
	
	// Add to buffer
	al.mu.Lock()
	al.eventBuffer = append(al.eventBuffer, event)
	al.stats.TotalEvents++
	al.stats.EventsByType[event.Type]++
	al.stats.EventsBySeverity[event.Severity]++
	al.stats.EventsByAction[event.Action]++
	al.stats.EventsBySource[event.Source]++
	al.stats.EventsBuffered++
	
	// Check if buffer needs flushing
	shouldFlush := len(al.eventBuffer) >= al.config.BufferSize
	al.mu.Unlock()
	
	// Log to structured logger
	if al.config.EnableStructuredLogs {
		al.logToStructuredLogger(event)
	}
	
	// Flush buffer if needed
	if shouldFlush {
		go al.flushBuffer(ctx)
	}
	
	// Check for real-time alerts
	if al.config.EnableRealTimeAlerts {
		al.checkAlertThresholds(event)
	}
}

func (al *AuditLogger) logToStructuredLogger(event *AuditEvent) {
	fields := logrus.Fields{
		"audit_id":    event.ID,
		"event_type":  event.Type,
		"severity":    event.Severity,
		"action":      event.Action,
		"source":      event.Source,
		"component":   event.Component,
		"timestamp":   event.Timestamp,
	}
	
	if event.UserID != "" {
		fields["user_id"] = event.UserID
	}
	if event.ClientIP != "" {
		fields["client_ip"] = event.ClientIP
	}
	if event.RequestID != "" {
		fields["request_id"] = event.RequestID
	}
	
	// Add threat analysis summary
	if event.ThreatAnalysis != nil {
		fields["is_threat"] = event.ThreatAnalysis.IsThreat
		fields["threat_level"] = event.ThreatAnalysis.ThreatLevel
		fields["confidence"] = event.ThreatAnalysis.Confidence
	}
	
	// Add behavior analysis summary
	if event.BehaviorAnalysis != nil {
		fields["is_anomalous"] = event.BehaviorAnalysis.IsAnomalous
		fields["anomaly_score"] = event.BehaviorAnalysis.AnomalyScore
	}
	
	// Log with appropriate level
	switch event.Severity {
	case AuditSeverityInfo:
		al.logger.WithFields(fields).Info("Audit event")
	case AuditSeverityWarning:
		al.logger.WithFields(fields).Warn("Audit event")
	case AuditSeverityError:
		al.logger.WithFields(fields).Error("Audit event")
	case AuditSeverityCritical:
		al.logger.WithFields(fields).Error("Critical audit event")
	}
}

func (al *AuditLogger) flushBuffer(ctx context.Context) {
	al.mu.Lock()
	if len(al.eventBuffer) == 0 {
		al.mu.Unlock()
		return
	}
	
	events := make([]*AuditEvent, len(al.eventBuffer))
	copy(events, al.eventBuffer)
	al.eventBuffer = al.eventBuffer[:0] // Clear buffer
	al.mu.Unlock()
	
	// Save events to storage
	if al.config.EnableDatabaseStorage && al.storage != nil {
		for _, event := range events {
			if err := al.storage.SaveAuditEvent(ctx, event); err != nil {
				al.mu.Lock()
				al.stats.StorageErrors++
				al.mu.Unlock()
				al.logger.Errorf("Failed to save audit event: %v", err)
			}
		}
	}
	
	al.mu.Lock()
	al.stats.EventsFlushed += int64(len(events))
	al.stats.LastFlush = time.Now()
	al.stats.LastUpdated = time.Now()
	al.mu.Unlock()
}

func (al *AuditLogger) calculateEventHash(event *AuditEvent) string {
	// Create a simplified hash of key event fields
	data := fmt.Sprintf("%s:%s:%s:%s:%v", 
		event.Timestamp.Format(time.RFC3339Nano),
		event.Type,
		event.Action,
		event.Source,
		event.Metadata)
	
	// In production, use proper cryptographic hash
	return fmt.Sprintf("hash-%x", len(data))
}

func (al *AuditLogger) maskSensitiveData(event *AuditEvent) {
	// Mask sensitive fields
	if event.UserAgent != "" {
		event.UserAgent = al.maskString(event.UserAgent)
	}
	
	if event.ThreatAnalysis != nil && len(event.ThreatAnalysis.Body) > 0 {
		event.ThreatAnalysis.Body = []byte("***MASKED***")
	}
	
	// Mask sensitive metadata
	if event.Metadata != nil {
		for key, value := range event.Metadata {
			if al.isSensitiveField(key) {
				if str, ok := value.(string); ok {
					event.Metadata[key] = al.maskString(str)
				}
			}
		}
	}
}

func (al *AuditLogger) maskString(s string) string {
	if len(s) <= 4 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

func (al *AuditLogger) isSensitiveField(field string) bool {
	sensitiveFields := []string{"password", "token", "key", "secret", "auth", "credential"}
	fieldLower := strings.ToLower(field)
	
	for _, sensitive := range sensitiveFields {
		if strings.Contains(fieldLower, sensitive) {
			return true
		}
	}
	return false
}

func (al *AuditLogger) checkAlertThresholds(event *AuditEvent) {
	// Check if event type exceeds alert threshold
	if threshold, exists := al.config.AlertThresholds[string(event.Type)]; exists {
		al.mu.RLock()
		count := al.stats.EventsByType[event.Type]
		al.mu.RUnlock()
		
		if count >= threshold {
			al.logger.Warnf("Alert threshold exceeded for event type %s: %d >= %d", 
				event.Type, count, threshold)
		}
	}
}

func (al *AuditLogger) mapThreatLevelToSeverity(level ThreatLevel) AuditSeverity {
	switch level {
	case ThreatLevelCritical:
		return AuditSeverityCritical
	case ThreatLevelHigh:
		return AuditSeverityError
	case ThreatLevelMedium:
		return AuditSeverityWarning
	case ThreatLevelLow, ThreatLevelNone:
		return AuditSeverityInfo
	default:
		return AuditSeverityInfo
	}
}

func (al *AuditLogger) generateThreatTags(result *ThreatAnalysisResult) []string {
	tags := []string{"threat_detection"}
	
	if result.IsThreat {
		tags = append(tags, "threat", string(result.ThreatType), string(result.ThreatLevel))
	} else {
		tags = append(tags, "safe", "no_threat")
	}
	
	return tags
}

// Public methods for management

func (al *AuditLogger) FlushNow(ctx context.Context) error {
	al.flushBuffer(ctx)
	return nil
}

func (al *AuditLogger) GetStats() *AuditStats {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	statsCopy := *al.stats
	statsCopy.EventsByType = make(map[AuditEventType]int64)
	statsCopy.EventsBySeverity = make(map[AuditSeverity]int64)
	statsCopy.EventsByAction = make(map[AuditAction]int64)
	statsCopy.EventsBySource = make(map[string]int64)
	
	for k, v := range al.stats.EventsByType {
		statsCopy.EventsByType[k] = v
	}
	for k, v := range al.stats.EventsBySeverity {
		statsCopy.EventsBySeverity[k] = v
	}
	for k, v := range al.stats.EventsByAction {
		statsCopy.EventsByAction[k] = v
	}
	for k, v := range al.stats.EventsBySource {
		statsCopy.EventsBySource[k] = v
	}
	
	return &statsCopy
}

func (al *AuditLogger) SetConfig(config *AuditConfig) {
	al.mu.Lock()
	defer al.mu.Unlock()
	
	al.config = config
	al.logger.Info("Updated audit logger configuration")
}

func (al *AuditLogger) GetConfig() *AuditConfig {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	configCopy := *al.config
	return &configCopy
}

// Helper functions

func generateAuditEventID() string {
	return fmt.Sprintf("audit-%d", time.Now().UnixNano())
}

// Default configurations

func getDefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:               true,
		LogLevel:              logrus.InfoLevel,
		EnableStructuredLogs:  true,
		EnableFileOutput:      true,
		EnableDatabaseStorage: true,
		EnableRealTimeAlerts:  true,
		BufferSize:            100,
		FlushInterval:         30 * time.Second,
		MaxEventSize:          1024 * 1024, // 1MB
		IncludeSensitiveData:  false,
		MaskSensitiveFields:   true,
		CompressLogs:          true,
		EncryptLogs:           false,
		LogRotationSize:       100 * 1024 * 1024, // 100MB
		LogRetentionDays:      90,
		AlertThresholds: map[string]int64{
			string(AuditEventThreatDetection):  1000,
			string(AuditEventSecurityIncident): 10,
			string(AuditEventError):            100,
		},
	}
}

func getDefaultAuditStats() *AuditStats {
	return &AuditStats{
		EventsByType:     make(map[AuditEventType]int64),
		EventsBySeverity: make(map[AuditSeverity]int64),
		EventsByAction:   make(map[AuditAction]int64),
		EventsBySource:   make(map[string]int64),
		LastUpdated:      time.Now(),
	}
}

func getDefaultRetentionPolicy() *RetentionPolicy {
	return &RetentionPolicy{
		DefaultRetention: 90 * 24 * time.Hour, // 90 days
		RetentionByType: map[AuditEventType]time.Duration{
			AuditEventThreatDetection:  180 * 24 * time.Hour, // 6 months
			AuditEventSecurityIncident: 7 * 365 * 24 * time.Hour, // 7 years
			AuditEventConfigChange:     7 * 365 * 24 * time.Hour, // 7 years
			AuditEventUserAction:       2 * 365 * 24 * time.Hour, // 2 years
		},
		RetentionBySeverity: map[AuditSeverity]time.Duration{
			AuditSeverityCritical: 7 * 365 * 24 * time.Hour, // 7 years
			AuditSeverityError:    365 * 24 * time.Hour,     // 1 year
			AuditSeverityWarning:  180 * 24 * time.Hour,     // 6 months
			AuditSeverityInfo:     90 * 24 * time.Hour,      // 90 days
		},
		ArchiveAfter:  30 * 24 * time.Hour, // 30 days
		DeleteAfter:   365 * 24 * time.Hour, // 1 year
		CompressAfter: 7 * 24 * time.Hour,   // 7 days
	}
}