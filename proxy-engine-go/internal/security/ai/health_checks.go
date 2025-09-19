package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// ThreatDetectorHealthCheck implements health check for threat detector
type ThreatDetectorHealthCheck struct {
	detector AIThreatDetector
	logger   *logrus.Logger
}

func (hc *ThreatDetectorHealthCheck) Name() string {
	return "threat_detector"
}

func (hc *ThreatDetectorHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{"storage", "models"},
	}
	
	// Check if threat detector is responsive
	testRequest := &ThreatAnalysisRequest{
		RequestID: "health-check",
		Timestamp: time.Now(),
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		URL:       "/health",
		Headers:   map[string]string{"User-Agent": "health-check"},
	}
	
	startTime := time.Now()
	result, err := hc.detector.AnalyzeRequest(ctx, testRequest)
	responseTime := time.Since(startTime)
	
	if err != nil {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "threat_detector_error",
			Severity:    IssueSeverityCritical,
			Title:       "Threat Detector Error",
			Description: fmt.Sprintf("Failed to analyze test request: %v", err),
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
	} else {
		health.Details["last_analysis_result"] = result
		health.Details["response_time_ms"] = responseTime.Milliseconds()
		health.Metrics["response_time"] = responseTime.Seconds()
		health.Metrics["confidence"] = result.Confidence
		health.ErrorRate = 0.0
		health.Availability = 1.0
		
		// Check response time threshold
		if responseTime > 5*time.Second {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "threat_detector_slow",
				Severity:    IssueSeverityWarning,
				Title:       "Slow Response Time",
				Description: fmt.Sprintf("Response time %.2fs exceeds threshold", responseTime.Seconds()),
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
	}
	
	// Get threat detector statistics
	stats, err := hc.detector.GetStats(ctx)
	if err == nil {
		health.Details["total_requests"] = stats.TotalRequests
		health.Details["threats_detected"] = stats.ThreatsDetected
		health.Details["model_accuracy"] = stats.ModelAccuracy
		health.Metrics["total_requests"] = float64(stats.TotalRequests)
		health.Metrics["threats_detected"] = float64(stats.ThreatsDetected)
		
		// Calculate threat detection rate
		if stats.TotalRequests > 0 {
			threatRate := float64(stats.ThreatsDetected) / float64(stats.TotalRequests)
			health.Metrics["threat_detection_rate"] = threatRate
		}
	}
	
	// Get health status
	healthStatus, err := hc.detector.GetHealth(ctx)
	if err == nil {
		health.Details["component_health"] = healthStatus
		if healthStatus.Overall != "healthy" {
			health.Status = HealthStatusDegraded
		}
	}
	
	return health
}

func (hc *ThreatDetectorHealthCheck) Dependencies() []string {
	return []string{"storage", "models"}
}

func (hc *ThreatDetectorHealthCheck) Weight() float64 {
	return 3.0 // High importance
}

// AdaptiveLearningHealthCheck implements health check for adaptive learning
type AdaptiveLearningHealthCheck struct {
	learning *AdaptiveLearningSystem
	logger   *logrus.Logger
}

func (hc *AdaptiveLearningHealthCheck) Name() string {
	return "adaptive_learning"
}

func (hc *AdaptiveLearningHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{"storage"},
	}
	
	// Get learning statistics
	stats := hc.learning.GetLearningStats()
	if stats != nil {
		health.Details["total_feedback"] = stats.TotalFeedback
		health.Details["model_updates"] = stats.ModelUpdates
		health.Details["feedback_accuracy"] = stats.FeedbackAccuracy
		health.Details["learning_effectiveness"] = stats.LearningEffectiveness
		
		health.Metrics["total_feedback"] = float64(stats.TotalFeedback)
		health.Metrics["model_updates"] = float64(stats.ModelUpdates)
		health.Metrics["feedback_accuracy"] = stats.FeedbackAccuracy
		health.Metrics["learning_effectiveness"] = stats.LearningEffectiveness
		
		// Check learning effectiveness
		if stats.LearningEffectiveness < 0.1 {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "low_learning_effectiveness",
				Severity:    IssueSeverityWarning,
				Title:       "Low Learning Effectiveness",
				Description: fmt.Sprintf("Learning effectiveness %.2f is below threshold", stats.LearningEffectiveness),
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		// Check if learning is stalled
		if time.Since(stats.LastUpdated) > 24*time.Hour {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "learning_stalled",
				Severity:    IssueSeverityWarning,
				Title:       "Learning System Stalled",
				Description: "No learning activity in the last 24 hours",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		health.ErrorRate = 0.0
		health.Availability = 1.0
	} else {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "learning_stats_unavailable",
			Severity:    IssueSeverityCritical,
			Title:       "Learning Statistics Unavailable",
			Description: "Unable to retrieve learning system statistics",
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
	}
	
	// Check configuration
	config := hc.learning.GetConfig()
	if config != nil {
		health.Details["enabled_learning"] = config.EnabledLearning
		health.Details["auto_retraining"] = config.EnableAutoRetraining
		health.Details["feedback_learning"] = config.EnableFeedbackLearning
		
		if !config.EnabledLearning {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "learning_disabled",
				Severity:    IssueSeverityWarning,
				Title:       "Learning Disabled",
				Description: "Adaptive learning is disabled in configuration",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
	}
	
	return health
}

func (hc *AdaptiveLearningHealthCheck) Dependencies() []string {
	return []string{"storage"}
}

func (hc *AdaptiveLearningHealthCheck) Weight() float64 {
	return 2.0
}

// AdaptiveRateLimiterHealthCheck implements health check for adaptive rate limiter
type AdaptiveRateLimiterHealthCheck struct {
	rateLimiter *AIAdaptiveRateLimiter
	logger      *logrus.Logger
}

func (hc *AdaptiveRateLimiterHealthCheck) Name() string {
	return "adaptive_rate_limiter"
}

func (hc *AdaptiveRateLimiterHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{"threat_detector"},
	}
	
	// Get rate limiter statistics
	stats := hc.rateLimiter.GetStats()
	if stats != nil {
		health.Details["requests_processed"] = stats.RequestsProcessed
		health.Details["threat_based_adjustments"] = stats.ThreatBasedAdjustments
		health.Details["behavioral_adjustments"] = stats.BehavioralAdjustments
		health.Details["average_multiplier"] = stats.AverageMultiplier
		health.Details["cache_hit_rate"] = stats.CacheHitRate
		health.Details["emergency_mode_activations"] = stats.EmergencyModeActivations
		
		health.Metrics["requests_processed"] = float64(stats.RequestsProcessed)
		health.Metrics["threat_based_adjustments"] = float64(stats.ThreatBasedAdjustments)
		health.Metrics["behavioral_adjustments"] = float64(stats.BehavioralAdjustments)
		health.Metrics["average_multiplier"] = stats.AverageMultiplier
		health.Metrics["cache_hit_rate"] = stats.CacheHitRate
		
		// Check if rate limiter is working effectively
		if stats.RequestsProcessed > 0 {
			adjustmentRate := float64(stats.ThreatBasedAdjustments+stats.BehavioralAdjustments) / float64(stats.RequestsProcessed)
			health.Metrics["adjustment_rate"] = adjustmentRate
			
			if adjustmentRate > 0.5 {
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, HealthIssue{
					ID:          "high_adjustment_rate",
					Severity:    IssueSeverityWarning,
					Title:       "High Rate Limit Adjustment Rate",
					Description: fmt.Sprintf("Adjustment rate %.2f%% is unusually high", adjustmentRate*100),
					Component:   hc.Name(),
					DetectedAt:  time.Now(),
				})
			}
		}
		
		// Check cache performance
		if stats.CacheHitRate < 0.5 {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "low_cache_hit_rate",
				Severity:    IssueSeverityWarning,
				Title:       "Low Cache Hit Rate",
				Description: fmt.Sprintf("Cache hit rate %.2f%% is below optimal", stats.CacheHitRate*100),
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		health.ErrorRate = 0.0
		health.Availability = 1.0
	} else {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "rate_limiter_stats_unavailable",
			Severity:    IssueSeverityCritical,
			Title:       "Rate Limiter Statistics Unavailable",
			Description: "Unable to retrieve rate limiter statistics",
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
	}
	
	// Check configuration
	config := hc.rateLimiter.GetConfig()
	if config != nil {
		health.Details["enabled"] = config.Enabled
		health.Details["threat_based_adjustment"] = config.ThreatBasedAdjustment
		health.Details["behavioral_adjustment"] = config.BehavioralAdjustment
		health.Details["emergency_mode"] = config.EmergencyMode
		
		if !config.Enabled {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "rate_limiter_disabled",
				Severity:    IssueSeverityWarning,
				Title:       "Adaptive Rate Limiter Disabled",
				Description: "Adaptive rate limiting is disabled in configuration",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		if config.EmergencyMode {
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "emergency_mode_active",
				Severity:    IssueSeverityWarning,
				Title:       "Emergency Mode Active",
				Description: "Rate limiter is in emergency mode",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
	}
	
	return health
}

func (hc *AdaptiveRateLimiterHealthCheck) Dependencies() []string {
	return []string{"threat_detector"}
}

func (hc *AdaptiveRateLimiterHealthCheck) Weight() float64 {
	return 2.0
}

// MiddlewareHealthCheck implements health check for AI security middleware
type MiddlewareHealthCheck struct {
	middleware *AISecurityMiddleware
	logger     *logrus.Logger
}

func (hc *MiddlewareHealthCheck) Name() string {
	return "middleware"
}

func (hc *MiddlewareHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{"threat_detector"},
	}
	
	// Get middleware statistics
	stats := hc.middleware.GetStats()
	if stats != nil {
		health.Details["requests_processed"] = stats.RequestsProcessed
		health.Details["threats_detected"] = stats.ThreatsDetected
		health.Details["requests_blocked"] = stats.RequestsBlocked
		health.Details["requests_challenged"] = stats.RequestsChallenged
		health.Details["average_analysis_time"] = stats.AverageAnalysisTime
		
		health.Metrics["requests_processed"] = float64(stats.RequestsProcessed)
		health.Metrics["threats_detected"] = float64(stats.ThreatsDetected)
		health.Metrics["requests_blocked"] = float64(stats.RequestsBlocked)
		health.Metrics["requests_challenged"] = float64(stats.RequestsChallenged)
		health.Metrics["average_analysis_time"] = stats.AverageAnalysisTime.Seconds()
		
		// Calculate threat detection rate
		if stats.RequestsProcessed > 0 {
			threatRate := float64(stats.ThreatsDetected) / float64(stats.RequestsProcessed)
			blockRate := float64(stats.RequestsBlocked) / float64(stats.RequestsProcessed)
			
			health.Metrics["threat_detection_rate"] = threatRate
			health.Metrics["block_rate"] = blockRate
			
			// Check if threat detection rate is unusually high
			if threatRate > 0.1 {
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, HealthIssue{
					ID:          "high_threat_rate",
					Severity:    IssueSeverityWarning,
					Title:       "High Threat Detection Rate",
					Description: fmt.Sprintf("Threat detection rate %.2f%% is unusually high", threatRate*100),
					Component:   hc.Name(),
					DetectedAt:  time.Now(),
				})
			}
		}
		
		// Check average analysis time
		if stats.AverageAnalysisTime > 1*time.Second {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "slow_analysis",
				Severity:    IssueSeverityWarning,
				Title:       "Slow Analysis Time",
				Description: fmt.Sprintf("Average analysis time %.2fs exceeds threshold", stats.AverageAnalysisTime.Seconds()),
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		health.ErrorRate = 0.0
		health.Availability = 1.0
	} else {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "middleware_stats_unavailable",
			Severity:    IssueSeverityCritical,
			Title:       "Middleware Statistics Unavailable",
			Description: "Unable to retrieve middleware statistics",
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
	}
	
	// Check configuration
	config := hc.middleware.GetConfig()
	if config != nil {
		health.Details["enabled"] = config.Enabled
		health.Details["blocking_enabled"] = config.BlockingEnabled
		health.Details["challenge_enabled"] = config.ChallengeEnabled
		health.Details["logging_enabled"] = config.LoggingEnabled
		
		if !config.Enabled {
			health.Status = HealthStatusCritical
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "middleware_disabled",
				Severity:    IssueSeverityCritical,
				Title:       "AI Security Middleware Disabled",
				Description: "AI security middleware is disabled in configuration",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
	}
	
	return health
}

func (hc *MiddlewareHealthCheck) Dependencies() []string {
	return []string{"threat_detector"}
}

func (hc *MiddlewareHealthCheck) Weight() float64 {
	return 2.5
}

// StorageHealthCheck implements health check for AI storage
type StorageHealthCheck struct {
	storage AIStorage
	logger  *logrus.Logger
}

func (hc *StorageHealthCheck) Name() string {
	return "storage"
}

func (hc *StorageHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{},
	}
	
	// Test storage connectivity with a simple operation
	testExample := &TrainingExample{
		ID:        "health-check",
		Features:  map[string]float64{"test": 1.0},
		Label:     false,
		Source:    "health-check",
		Timestamp: time.Now(),
	}
	
	startTime := time.Now()
	
	// Test save operation
	err := hc.storage.SaveTrainingExample(ctx, testExample)
	if err != nil {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "storage_write_error",
			Severity:    IssueSeverityCritical,
			Title:       "Storage Write Error",
			Description: fmt.Sprintf("Failed to write to storage: %v", err),
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
		return health
	}
	
	// Test load operation
	examples, err := hc.storage.LoadTrainingExamples(ctx, 1, 0)
	responseTime := time.Since(startTime)
	
	if err != nil {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "storage_read_error",
			Severity:    IssueSeverityCritical,
			Title:       "Storage Read Error",
			Description: fmt.Sprintf("Failed to read from storage: %v", err),
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
		return health
	}
	
	// Clean up test data
	hc.storage.DeleteTrainingExample(ctx, "health-check")
	
	health.Details["response_time_ms"] = responseTime.Milliseconds()
	health.Details["examples_loaded"] = len(examples)
	health.Metrics["response_time"] = responseTime.Seconds()
	health.Metrics["examples_count"] = float64(len(examples))
	
	// Check response time
	if responseTime > 2*time.Second {
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "storage_slow_response",
			Severity:    IssueSeverityWarning,
			Title:       "Slow Storage Response",
			Description: fmt.Sprintf("Storage response time %.2fs exceeds threshold", responseTime.Seconds()),
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
	}
	
	// Test additional storage operations
	policies, err := hc.storage.LoadThreatPolicies(ctx)
	if err != nil {
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "policies_load_error",
			Severity:    IssueSeverityWarning,
			Title:       "Failed to Load Policies",
			Description: fmt.Sprintf("Failed to load threat policies: %v", err),
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
	} else {
		health.Details["policies_loaded"] = policies != nil
	}
	
	health.ErrorRate = 0.0
	health.Availability = 1.0
	
	return health
}

func (hc *StorageHealthCheck) Dependencies() []string {
	return []string{}
}

func (hc *StorageHealthCheck) Weight() float64 {
	return 2.5
}

// AuditLoggerHealthCheck implements health check for audit logger
type AuditLoggerHealthCheck struct {
	auditLogger *AuditLogger
	logger      *logrus.Logger
}

func (hc *AuditLoggerHealthCheck) Name() string {
	return "audit_logger"
}

func (hc *AuditLoggerHealthCheck) Check(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		Name:         hc.Name(),
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		Details:      make(map[string]interface{}),
		Metrics:      make(map[string]float64),
		Issues:       make([]HealthIssue, 0),
		Dependencies: []string{"storage"},
	}
	
	// Get audit logger statistics
	stats := hc.auditLogger.GetStats()
	if stats != nil {
		health.Details["total_events"] = stats.TotalEvents
		health.Details["events_buffered"] = stats.EventsBuffered
		health.Details["events_flushed"] = stats.EventsFlushed
		health.Details["events_dropped"] = stats.EventsDropped
		health.Details["storage_errors"] = stats.StorageErrors
		health.Details["last_flush"] = stats.LastFlush
		
		health.Metrics["total_events"] = float64(stats.TotalEvents)
		health.Metrics["events_buffered"] = float64(stats.EventsBuffered)
		health.Metrics["events_flushed"] = float64(stats.EventsFlushed)
		health.Metrics["events_dropped"] = float64(stats.EventsDropped)
		health.Metrics["storage_errors"] = float64(stats.StorageErrors)
		
		// Check for dropped events
		if stats.EventsDropped > 0 {
			dropRate := float64(stats.EventsDropped) / float64(stats.TotalEvents)
			health.Metrics["drop_rate"] = dropRate
			
			if dropRate > 0.01 { // 1% drop rate threshold
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, HealthIssue{
					ID:          "high_drop_rate",
					Severity:    IssueSeverityWarning,
					Title:       "High Event Drop Rate",
					Description: fmt.Sprintf("Event drop rate %.2f%% exceeds threshold", dropRate*100),
					Component:   hc.Name(),
					DetectedAt:  time.Now(),
				})
			}
		}
		
		// Check for storage errors
		if stats.StorageErrors > 0 {
			errorRate := float64(stats.StorageErrors) / float64(stats.TotalEvents)
			health.Metrics["error_rate"] = errorRate
			
			if errorRate > 0.05 { // 5% error rate threshold
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, HealthIssue{
					ID:          "high_storage_error_rate",
					Severity:    IssueSeverityWarning,
					Title:       "High Storage Error Rate",
					Description: fmt.Sprintf("Storage error rate %.2f%% exceeds threshold", errorRate*100),
					Component:   hc.Name(),
					DetectedAt:  time.Now(),
				})
			}
		}
		
		// Check if flushing is working
		if time.Since(stats.LastFlush) > 5*time.Minute && stats.EventsBuffered > 0 {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "flush_stalled",
				Severity:    IssueSeverityWarning,
				Title:       "Event Flushing Stalled",
				Description: "Events have not been flushed in over 5 minutes",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
		
		health.ErrorRate = float64(stats.StorageErrors) / float64(stats.TotalEvents)
		health.Availability = 1.0
	} else {
		health.Status = HealthStatusCritical
		health.Issues = append(health.Issues, HealthIssue{
			ID:          "audit_logger_stats_unavailable",
			Severity:    IssueSeverityCritical,
			Title:       "Audit Logger Statistics Unavailable",
			Description: "Unable to retrieve audit logger statistics",
			Component:   hc.Name(),
			DetectedAt:  time.Now(),
		})
		health.ErrorRate = 1.0
		health.Availability = 0.0
	}
	
	// Check configuration
	config := hc.auditLogger.GetConfig()
	if config != nil {
		health.Details["enabled"] = config.Enabled
		health.Details["structured_logs"] = config.EnableStructuredLogs
		health.Details["database_storage"] = config.EnableDatabaseStorage
		health.Details["buffer_size"] = config.BufferSize
		
		if !config.Enabled {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, HealthIssue{
				ID:          "audit_logger_disabled",
				Severity:    IssueSeverityWarning,
				Title:       "Audit Logger Disabled",
				Description: "Audit logging is disabled in configuration",
				Component:   hc.Name(),
				DetectedAt:  time.Now(),
			})
		}
	}
	
	return health
}

func (hc *AuditLoggerHealthCheck) Dependencies() []string {
	return []string{"storage"}
}

func (hc *AuditLoggerHealthCheck) Weight() float64 {
	return 1.5
}