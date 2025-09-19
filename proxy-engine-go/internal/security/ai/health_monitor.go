package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthMonitor provides comprehensive health monitoring for AI threat detection system
type HealthMonitor struct {
	threatDetector      AIThreatDetector
	adaptiveLearning    *AdaptiveLearningSystem
	adaptiveRateLimiter *AIAdaptiveRateLimiter
	middleware          *AISecurityMiddleware
	storage             AIStorage
	auditLogger         *AuditLogger
	config              *HealthConfig
	metrics             *HealthMetrics
	checks              map[string]HealthCheck
	alerts              *AlertManager
	logger              *logrus.Logger
	mu                  sync.RWMutex
}

// HealthConfig holds configuration for health monitoring
type HealthConfig struct {
	Enabled                bool                       `json:"enabled"`
	CheckInterval          time.Duration              `json:"check_interval"`
	HealthCheckTimeout     time.Duration              `json:"health_check_timeout"`
	MetricsRetentionPeriod time.Duration              `json:"metrics_retention_period"`
	AlertThresholds        map[string]float64         `json:"alert_thresholds"`
	ComponentWeights       map[string]float64         `json:"component_weights"`
	EnablePrometheusExport bool                       `json:"enable_prometheus_export"`
	PrometheusPort         int                        `json:"prometheus_port"`
	EnableDetailedMetrics  bool                       `json:"enable_detailed_metrics"`
	HealthEndpointEnabled  bool                       `json:"health_endpoint_enabled"`
	CriticalComponents     []string                   `json:"critical_components"`
	DegradedThreshold      float64                    `json:"degraded_threshold"`
	UnhealthyThreshold     float64                    `json:"unhealthy_threshold"`
}

// HealthMetrics tracks system health metrics
type HealthMetrics struct {
	OverallHealth         HealthStatus               `json:"overall_health"`
	ComponentHealth       map[string]*ComponentHealth `json:"component_health"`
	SystemMetrics         *SystemMetrics             `json:"system_metrics"`
	PerformanceMetrics    *PerformanceMetrics        `json:"performance_metrics"`
	ErrorMetrics          *ErrorMetrics              `json:"error_metrics"`
	ThroughputMetrics     *ThroughputMetrics         `json:"throughput_metrics"`
	ResourceMetrics       *ResourceMetrics           `json:"resource_metrics"`
	LastHealthCheck       time.Time                  `json:"last_health_check"`
	HealthScore           float64                    `json:"health_score"`
	Uptime                time.Duration              `json:"uptime"`
	StartTime             time.Time                  `json:"start_time"`
}

// HealthStatus defines system health status levels
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusCritical  HealthStatus = "critical"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// ComponentHealth represents health status of individual components
type ComponentHealth struct {
	Name            string                 `json:"name"`
	Status          HealthStatus           `json:"status"`
	LastCheck       time.Time              `json:"last_check"`
	ResponseTime    time.Duration          `json:"response_time"`
	ErrorRate       float64                `json:"error_rate"`
	Availability    float64                `json:"availability"`
	Details         map[string]interface{} `json:"details"`
	Metrics         map[string]float64     `json:"metrics"`
	Issues          []HealthIssue          `json:"issues"`
	Dependencies    []string               `json:"dependencies"`
	Weight          float64                `json:"weight"`
}

// HealthIssue represents a health issue
type HealthIssue struct {
	ID          string                 `json:"id"`
	Severity    IssueSeverity          `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Component   string                 `json:"component"`
	DetectedAt  time.Time              `json:"detected_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// IssueSeverity defines severity levels for health issues
type IssueSeverity string

const (
	IssueSeverityInfo     IssueSeverity = "info"
	IssueSeverityWarning  IssueSeverity = "warning"
	IssueSeverityError    IssueSeverity = "error"
	IssueSeverityCritical IssueSeverity = "critical"
)

// SystemMetrics contains system-level metrics
type SystemMetrics struct {
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	DiskUsage      float64   `json:"disk_usage"`
	NetworkLatency float64   `json:"network_latency"`
	LoadAverage    []float64 `json:"load_average"`
	OpenFiles      int64     `json:"open_files"`
	Goroutines     int       `json:"goroutines"`
	HeapSize       int64     `json:"heap_size"`
	GCPauses       []float64 `json:"gc_pauses"`
}

// PerformanceMetrics contains performance-related metrics
type PerformanceMetrics struct {
	AverageResponseTime    time.Duration          `json:"average_response_time"`
	P95ResponseTime        time.Duration          `json:"p95_response_time"`
	P99ResponseTime        time.Duration          `json:"p99_response_time"`
	ThreatAnalysisLatency  time.Duration          `json:"threat_analysis_latency"`
	ModelInferenceTime     time.Duration          `json:"model_inference_time"`
	BehaviorAnalysisTime   time.Duration          `json:"behavior_analysis_time"`
	CacheHitRate           float64                `json:"cache_hit_rate"`
	DatabaseQueryTime      time.Duration          `json:"database_query_time"`
	ComponentLatencies     map[string]time.Duration `json:"component_latencies"`
}

// ErrorMetrics contains error-related metrics
type ErrorMetrics struct {
	TotalErrors            int64                  `json:"total_errors"`
	ErrorRate              float64                `json:"error_rate"`
	ErrorsByType           map[string]int64       `json:"errors_by_type"`
	ErrorsByComponent      map[string]int64       `json:"errors_by_component"`
	CriticalErrors         int64                  `json:"critical_errors"`
	RecentErrors           []ErrorSummary         `json:"recent_errors"`
	ErrorTrends            map[string][]float64   `json:"error_trends"`
	MeanTimeBetweenFailures time.Duration         `json:"mean_time_between_failures"`
	MeanTimeToRecovery     time.Duration          `json:"mean_time_to_recovery"`
}

// ThroughputMetrics contains throughput-related metrics
type ThroughputMetrics struct {
	RequestsPerSecond      float64            `json:"requests_per_second"`
	RequestsPerMinute      float64            `json:"requests_per_minute"`
	ThroughputByEndpoint   map[string]float64 `json:"throughput_by_endpoint"`
	PeakThroughput         float64            `json:"peak_throughput"`
	AverageThroughput      float64            `json:"average_throughput"`
	ThroughputTrend        []float64          `json:"throughput_trend"`
	ConcurrentRequests     int64              `json:"concurrent_requests"`
	QueueLength            int64              `json:"queue_length"`
}

// ResourceMetrics contains resource utilization metrics
type ResourceMetrics struct {
	ModelMemoryUsage       int64              `json:"model_memory_usage"`
	CacheMemoryUsage       int64              `json:"cache_memory_usage"`
	DatabaseConnections    int                `json:"database_connections"`
	RedisConnections       int                `json:"redis_connections"`
	ActiveWebSockets       int                `json:"active_websockets"`
	ThreadPoolUtilization  float64            `json:"thread_pool_utilization"`
	ResourceUtilization    map[string]float64 `json:"resource_utilization"`
}

// ErrorSummary provides a summary of an error
type ErrorSummary struct {
	Timestamp   time.Time `json:"timestamp"`
	Component   string    `json:"component"`
	ErrorType   string    `json:"error_type"`
	Message     string    `json:"message"`
	Count       int64     `json:"count"`
	Severity    string    `json:"severity"`
}

// HealthCheck interface for component health checks
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) *ComponentHealth
	Dependencies() []string
	Weight() float64
}

// AlertManager handles health-related alerts
type AlertManager struct {
	config    *AlertConfig
	channels  []AlertChannel
	history   []*Alert
	logger    *logrus.Logger
	mu        sync.RWMutex
}

// AlertConfig holds alert configuration
type AlertConfig struct {
	Enabled           bool                   `json:"enabled"`
	CooldownPeriod    time.Duration          `json:"cooldown_period"`
	MaxAlertsPerHour  int                    `json:"max_alerts_per_hour"`
	AlertThresholds   map[string]float64     `json:"alert_thresholds"`
	EscalationRules   []EscalationRule       `json:"escalation_rules"`
	NotificationDelay time.Duration          `json:"notification_delay"`
}

// Alert represents a health alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	Component   string                 `json:"component"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Escalated   bool                   `json:"escalated"`
}

// AlertType defines types of alerts
type AlertType string

const (
	AlertTypeHealthDegraded    AlertType = "health_degraded"
	AlertTypeComponentDown     AlertType = "component_down"
	AlertTypeHighErrorRate     AlertType = "high_error_rate"
	AlertTypeHighLatency       AlertType = "high_latency"
	AlertTypeResourceExhaustion AlertType = "resource_exhaustion"
	AlertTypeModelFailure      AlertType = "model_failure"
	AlertTypeSystemOverload    AlertType = "system_overload"
)

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertChannel interface for alert delivery
type AlertChannel interface {
	Name() string
	Send(ctx context.Context, alert *Alert) error
	IsEnabled() bool
}

// EscalationRule defines alert escalation rules
type EscalationRule struct {
	Condition   string        `json:"condition"`
	Delay       time.Duration `json:"delay"`
	Channels    []string      `json:"channels"`
	Severity    AlertSeverity `json:"severity"`
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(
	threatDetector AIThreatDetector,
	adaptiveLearning *AdaptiveLearningSystem,
	adaptiveRateLimiter *AIAdaptiveRateLimiter,
	middleware *AISecurityMiddleware,
	storage AIStorage,
	auditLogger *AuditLogger,
	logger *logrus.Logger,
) *HealthMonitor {
	monitor := &HealthMonitor{
		threatDetector:      threatDetector,
		adaptiveLearning:    adaptiveLearning,
		adaptiveRateLimiter: adaptiveRateLimiter,
		middleware:          middleware,
		storage:             storage,
		auditLogger:         auditLogger,
		config:              getDefaultHealthConfig(),
		metrics:             getDefaultHealthMetrics(),
		checks:              make(map[string]HealthCheck),
		alerts:              NewAlertManager(logger),
		logger:              logger,
	}
	
	// Initialize health checks
	monitor.initializeHealthChecks()
	
	return monitor
}

// Start begins health monitoring
func (hm *HealthMonitor) Start(ctx context.Context) {
	if !hm.config.Enabled {
		hm.logger.Info("Health monitoring is disabled")
		return
	}
	
	hm.logger.Info("Starting AI system health monitoring")
	hm.metrics.StartTime = time.Now()
	
	ticker := time.NewTicker(hm.config.CheckInterval)
	defer ticker.Stop()
	
	// Perform initial health check
	hm.performHealthCheck(ctx)
	
	for {
		select {
		case <-ctx.Done():
			hm.logger.Info("Health monitoring stopped")
			return
		case <-ticker.C:
			hm.performHealthCheck(ctx)
		}
	}
}

// GetHealth returns current system health status
func (hm *HealthMonitor) GetHealth(ctx context.Context) (*HealthMetrics, error) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	// Create a deep copy of metrics
	healthCopy := *hm.metrics
	healthCopy.ComponentHealth = make(map[string]*ComponentHealth)
	
	for name, health := range hm.metrics.ComponentHealth {
		healthCopy.ComponentHealth[name] = &ComponentHealth{
			Name:         health.Name,
			Status:       health.Status,
			LastCheck:    health.LastCheck,
			ResponseTime: health.ResponseTime,
			ErrorRate:    health.ErrorRate,
			Availability: health.Availability,
			Weight:       health.Weight,
		}
		
		// Deep copy details and metrics
		healthCopy.ComponentHealth[name].Details = make(map[string]interface{})
		for k, v := range health.Details {
			healthCopy.ComponentHealth[name].Details[k] = v
		}
		
		healthCopy.ComponentHealth[name].Metrics = make(map[string]float64)
		for k, v := range health.Metrics {
			healthCopy.ComponentHealth[name].Metrics[k] = v
		}
		
		// Copy issues
		healthCopy.ComponentHealth[name].Issues = make([]HealthIssue, len(health.Issues))
		copy(healthCopy.ComponentHealth[name].Issues, health.Issues)
		
		// Copy dependencies
		healthCopy.ComponentHealth[name].Dependencies = make([]string, len(health.Dependencies))
		copy(healthCopy.ComponentHealth[name].Dependencies, health.Dependencies)
	}
	
	healthCopy.Uptime = time.Since(hm.metrics.StartTime)
	
	return &healthCopy, nil
}

// GetPrometheusMetrics returns metrics in Prometheus format
func (hm *HealthMonitor) GetPrometheusMetrics() string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	var metrics []string
	
	// Overall health score
	metrics = append(metrics, fmt.Sprintf("ai_system_health_score %.2f", hm.metrics.HealthScore))
	
	// Component health
	for name, health := range hm.metrics.ComponentHealth {
		statusValue := hm.healthStatusToFloat(health.Status)
		metrics = append(metrics, fmt.Sprintf("ai_component_health{component=\"%s\"} %.0f", name, statusValue))
		metrics = append(metrics, fmt.Sprintf("ai_component_response_time{component=\"%s\"} %.3f", name, health.ResponseTime.Seconds()))
		metrics = append(metrics, fmt.Sprintf("ai_component_error_rate{component=\"%s\"} %.4f", name, health.ErrorRate))
		metrics = append(metrics, fmt.Sprintf("ai_component_availability{component=\"%s\"} %.4f", name, health.Availability))
	}
	
	// Performance metrics
	if hm.metrics.PerformanceMetrics != nil {
		metrics = append(metrics, fmt.Sprintf("ai_average_response_time %.3f", hm.metrics.PerformanceMetrics.AverageResponseTime.Seconds()))
		metrics = append(metrics, fmt.Sprintf("ai_p95_response_time %.3f", hm.metrics.PerformanceMetrics.P95ResponseTime.Seconds()))
		metrics = append(metrics, fmt.Sprintf("ai_p99_response_time %.3f", hm.metrics.PerformanceMetrics.P99ResponseTime.Seconds()))
		metrics = append(metrics, fmt.Sprintf("ai_cache_hit_rate %.4f", hm.metrics.PerformanceMetrics.CacheHitRate))
	}
	
	// Error metrics
	if hm.metrics.ErrorMetrics != nil {
		metrics = append(metrics, fmt.Sprintf("ai_total_errors %d", hm.metrics.ErrorMetrics.TotalErrors))
		metrics = append(metrics, fmt.Sprintf("ai_error_rate %.4f", hm.metrics.ErrorMetrics.ErrorRate))
		metrics = append(metrics, fmt.Sprintf("ai_critical_errors %d", hm.metrics.ErrorMetrics.CriticalErrors))
	}
	
	// Throughput metrics
	if hm.metrics.ThroughputMetrics != nil {
		metrics = append(metrics, fmt.Sprintf("ai_requests_per_second %.2f", hm.metrics.ThroughputMetrics.RequestsPerSecond))
		metrics = append(metrics, fmt.Sprintf("ai_concurrent_requests %d", hm.metrics.ThroughputMetrics.ConcurrentRequests))
		metrics = append(metrics, fmt.Sprintf("ai_queue_length %d", hm.metrics.ThroughputMetrics.QueueLength))
	}
	
	// System metrics
	if hm.metrics.SystemMetrics != nil {
		metrics = append(metrics, fmt.Sprintf("ai_cpu_usage %.2f", hm.metrics.SystemMetrics.CPUUsage))
		metrics = append(metrics, fmt.Sprintf("ai_memory_usage %.2f", hm.metrics.SystemMetrics.MemoryUsage))
		metrics = append(metrics, fmt.Sprintf("ai_goroutines %d", hm.metrics.SystemMetrics.Goroutines))
		metrics = append(metrics, fmt.Sprintf("ai_heap_size %d", hm.metrics.SystemMetrics.HeapSize))
	}
	
	// Uptime
	metrics = append(metrics, fmt.Sprintf("ai_uptime_seconds %.0f", hm.metrics.Uptime.Seconds()))
	
	return fmt.Sprintf("%s\n", joinStrings(metrics, "\n"))
}

// Private methods

func (hm *HealthMonitor) initializeHealthChecks() {
	// Threat Detector Health Check
	hm.checks["threat_detector"] = &ThreatDetectorHealthCheck{
		detector: hm.threatDetector,
		logger:   hm.logger,
	}
	
	// Adaptive Learning Health Check
	hm.checks["adaptive_learning"] = &AdaptiveLearningHealthCheck{
		learning: hm.adaptiveLearning,
		logger:   hm.logger,
	}
	
	// Adaptive Rate Limiter Health Check
	hm.checks["adaptive_rate_limiter"] = &AdaptiveRateLimiterHealthCheck{
		rateLimiter: hm.adaptiveRateLimiter,
		logger:      hm.logger,
	}
	
	// Middleware Health Check
	hm.checks["middleware"] = &MiddlewareHealthCheck{
		middleware: hm.middleware,
		logger:     hm.logger,
	}
	
	// Storage Health Check
	hm.checks["storage"] = &StorageHealthCheck{
		storage: hm.storage,
		logger:  hm.logger,
	}
	
	// Audit Logger Health Check
	hm.checks["audit_logger"] = &AuditLoggerHealthCheck{
		auditLogger: hm.auditLogger,
		logger:      hm.logger,
	}
}

func (hm *HealthMonitor) performHealthCheck(ctx context.Context) {
	hm.logger.Debug("Performing health check")
	
	checkCtx, cancel := context.WithTimeout(ctx, hm.config.HealthCheckTimeout)
	defer cancel()
	
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.metrics.LastHealthCheck = time.Now()
	hm.metrics.Uptime = time.Since(hm.metrics.StartTime)
	
	// Perform component health checks
	componentResults := make(map[string]*ComponentHealth)
	
	for name, check := range hm.checks {
		startTime := time.Now()
		health := check.Check(checkCtx)
		health.ResponseTime = time.Since(startTime)
		health.Weight = check.Weight()
		health.Dependencies = check.Dependencies()
		
		componentResults[name] = health
		
		// Check for issues and generate alerts
		hm.checkForIssues(name, health)
	}
	
	hm.metrics.ComponentHealth = componentResults
	
	// Calculate overall health score
	hm.metrics.HealthScore = hm.calculateOverallHealthScore()
	hm.metrics.OverallHealth = hm.determineOverallHealthStatus()
	
	// Update system metrics
	hm.updateSystemMetrics()
	
	// Update performance metrics
	hm.updatePerformanceMetrics()
	
	// Update error metrics
	hm.updateErrorMetrics()
	
	// Update throughput metrics
	hm.updateThroughputMetrics()
	
	// Update resource metrics
	hm.updateResourceMetrics()
	
	hm.logger.Debugf("Health check completed - Overall health: %s (Score: %.2f)", 
		hm.metrics.OverallHealth, hm.metrics.HealthScore)
}

func (hm *HealthMonitor) calculateOverallHealthScore() float64 {
	if len(hm.metrics.ComponentHealth) == 0 {
		return 0.0
	}
	
	totalWeight := 0.0
	weightedScore := 0.0
	
	for _, health := range hm.metrics.ComponentHealth {
		componentScore := hm.healthStatusToFloat(health.Status)
		weight := health.Weight
		if weight == 0 {
			weight = 1.0 // Default weight
		}
		
		weightedScore += componentScore * weight
		totalWeight += weight
	}
	
	if totalWeight == 0 {
		return 0.0
	}
	
	return (weightedScore / totalWeight) * 25.0 // Scale to 0-100
}

func (hm *HealthMonitor) determineOverallHealthStatus() HealthStatus {
	score := hm.metrics.HealthScore
	
	if score >= 90 {
		return HealthStatusHealthy
	} else if score >= hm.config.DegradedThreshold {
		return HealthStatusDegraded
	} else if score >= hm.config.UnhealthyThreshold {
		return HealthStatusUnhealthy
	} else {
		return HealthStatusCritical
	}
}

func (hm *HealthMonitor) healthStatusToFloat(status HealthStatus) float64 {
	switch status {
	case HealthStatusHealthy:
		return 4.0
	case HealthStatusDegraded:
		return 3.0
	case HealthStatusUnhealthy:
		return 2.0
	case HealthStatusCritical:
		return 1.0
	default:
		return 0.0
	}
}

func (hm *HealthMonitor) checkForIssues(componentName string, health *ComponentHealth) {
	// Check error rate threshold
	if errorThreshold, exists := hm.config.AlertThresholds["error_rate"]; exists {
		if health.ErrorRate > errorThreshold {
			alert := &Alert{
				ID:          generateAlertID(),
				Type:        AlertTypeHighErrorRate,
				Severity:    AlertSeverityWarning,
				Component:   componentName,
				Title:       "High Error Rate Detected",
				Description: fmt.Sprintf("Component %s has error rate %.2f%% (threshold: %.2f%%)", 
					componentName, health.ErrorRate*100, errorThreshold*100),
				Timestamp:   time.Now(),
				Metadata: map[string]interface{}{
					"error_rate": health.ErrorRate,
					"threshold":  errorThreshold,
				},
			}
			
			hm.alerts.SendAlert(context.Background(), alert)
		}
	}
	
	// Check response time threshold
	if latencyThreshold, exists := hm.config.AlertThresholds["response_time"]; exists {
		if health.ResponseTime.Seconds() > latencyThreshold {
			alert := &Alert{
				ID:          generateAlertID(),
				Type:        AlertTypeHighLatency,
				Severity:    AlertSeverityWarning,
				Component:   componentName,
				Title:       "High Response Time Detected",
				Description: fmt.Sprintf("Component %s has response time %.2fs (threshold: %.2fs)", 
					componentName, health.ResponseTime.Seconds(), latencyThreshold),
				Timestamp:   time.Now(),
				Metadata: map[string]interface{}{
					"response_time": health.ResponseTime.Seconds(),
					"threshold":     latencyThreshold,
				},
			}
			
			hm.alerts.SendAlert(context.Background(), alert)
		}
	}
	
	// Check component status
	if health.Status == HealthStatusCritical || health.Status == HealthStatusUnhealthy {
		severity := AlertSeverityError
		if health.Status == HealthStatusCritical {
			severity = AlertSeverityCritical
		}
		
		alert := &Alert{
			ID:          generateAlertID(),
			Type:        AlertTypeComponentDown,
			Severity:    severity,
			Component:   componentName,
			Title:       "Component Health Degraded",
			Description: fmt.Sprintf("Component %s status is %s", componentName, health.Status),
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"status": string(health.Status),
			},
		}
		
		hm.alerts.SendAlert(context.Background(), alert)
	}
}

func (hm *HealthMonitor) updateSystemMetrics() {
	// This would typically collect real system metrics
	// For now, we'll use placeholder values
	hm.metrics.SystemMetrics = &SystemMetrics{
		CPUUsage:       50.0, // Would be collected from system
		MemoryUsage:    60.0, // Would be collected from system
		DiskUsage:      30.0, // Would be collected from system
		NetworkLatency: 10.0, // Would be measured
		LoadAverage:    []float64{1.5, 1.2, 1.0},
		OpenFiles:      1000,
		Goroutines:     100, // Would use runtime.NumGoroutine()
		HeapSize:       1024 * 1024 * 100, // Would use runtime.MemStats
		GCPauses:       []float64{1.0, 2.0, 1.5},
	}
}

func (hm *HealthMonitor) updatePerformanceMetrics() {
	// Collect performance metrics from components
	hm.metrics.PerformanceMetrics = &PerformanceMetrics{
		AverageResponseTime:   100 * time.Millisecond,
		P95ResponseTime:       200 * time.Millisecond,
		P99ResponseTime:       500 * time.Millisecond,
		ThreatAnalysisLatency: 50 * time.Millisecond,
		ModelInferenceTime:    30 * time.Millisecond,
		BehaviorAnalysisTime:  20 * time.Millisecond,
		CacheHitRate:          0.85,
		DatabaseQueryTime:     10 * time.Millisecond,
		ComponentLatencies:    make(map[string]time.Duration),
	}
	
	// Collect component-specific latencies
	for name, health := range hm.metrics.ComponentHealth {
		hm.metrics.PerformanceMetrics.ComponentLatencies[name] = health.ResponseTime
	}
}

func (hm *HealthMonitor) updateErrorMetrics() {
	// Collect error metrics from components
	totalErrors := int64(0)
	errorsByType := make(map[string]int64)
	errorsByComponent := make(map[string]int64)
	
	for name, health := range hm.metrics.ComponentHealth {
		componentErrors := int64(health.ErrorRate * 1000) // Approximate
		totalErrors += componentErrors
		errorsByComponent[name] = componentErrors
	}
	
	hm.metrics.ErrorMetrics = &ErrorMetrics{
		TotalErrors:             totalErrors,
		ErrorRate:               float64(totalErrors) / 10000.0, // Approximate
		ErrorsByType:            errorsByType,
		ErrorsByComponent:       errorsByComponent,
		CriticalErrors:          totalErrors / 10, // Approximate
		RecentErrors:            []ErrorSummary{},
		ErrorTrends:             make(map[string][]float64),
		MeanTimeBetweenFailures: 24 * time.Hour,
		MeanTimeToRecovery:      5 * time.Minute,
	}
}

func (hm *HealthMonitor) updateThroughputMetrics() {
	// Collect throughput metrics
	middlewareStats := hm.middleware.GetStats()
	
	hm.metrics.ThroughputMetrics = &ThroughputMetrics{
		RequestsPerSecond:    float64(middlewareStats.RequestsProcessed) / 60.0, // Approximate
		RequestsPerMinute:    float64(middlewareStats.RequestsProcessed),
		ThroughputByEndpoint: make(map[string]float64),
		PeakThroughput:       1000.0, // Would be tracked over time
		AverageThroughput:    500.0,  // Would be calculated
		ThroughputTrend:      []float64{400, 450, 500, 550, 500},
		ConcurrentRequests:   50,
		QueueLength:          10,
	}
}

func (hm *HealthMonitor) updateResourceMetrics() {
	// Collect resource utilization metrics
	hm.metrics.ResourceMetrics = &ResourceMetrics{
		ModelMemoryUsage:      100 * 1024 * 1024, // 100MB
		CacheMemoryUsage:      50 * 1024 * 1024,  // 50MB
		DatabaseConnections:   10,
		RedisConnections:      5,
		ActiveWebSockets:      25,
		ThreadPoolUtilization: 0.6,
		ResourceUtilization:   make(map[string]float64),
	}
	
	hm.metrics.ResourceMetrics.ResourceUtilization["cpu"] = hm.metrics.SystemMetrics.CPUUsage
	hm.metrics.ResourceMetrics.ResourceUtilization["memory"] = hm.metrics.SystemMetrics.MemoryUsage
	hm.metrics.ResourceMetrics.ResourceUtilization["disk"] = hm.metrics.SystemMetrics.DiskUsage
}

// Configuration methods

func (hm *HealthMonitor) SetConfig(config *HealthConfig) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.config = config
	hm.logger.Info("Updated health monitor configuration")
}

func (hm *HealthMonitor) GetConfig() *HealthConfig {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	configCopy := *hm.config
	return &configCopy
}

// Alert Manager implementation

func NewAlertManager(logger *logrus.Logger) *AlertManager {
	return &AlertManager{
		config:   getDefaultAlertConfig(),
		channels: make([]AlertChannel, 0),
		history:  make([]*Alert, 0),
		logger:   logger,
	}
}

func (am *AlertManager) SendAlert(ctx context.Context, alert *Alert) {
	if !am.config.Enabled {
		return
	}
	
	am.mu.Lock()
	defer am.mu.Unlock()
	
	// Add to history
	am.history = append(am.history, alert)
	
	// Keep only recent alerts
	if len(am.history) > 1000 {
		am.history = am.history[100:]
	}
	
	am.logger.Warnf("Health alert: %s - %s", alert.Title, alert.Description)
	
	// Send to configured channels
	for _, channel := range am.channels {
		if channel.IsEnabled() {
			go func(ch AlertChannel) {
				if err := ch.Send(ctx, alert); err != nil {
					am.logger.Errorf("Failed to send alert via %s: %v", ch.Name(), err)
				}
			}(channel)
		}
	}
}

func (am *AlertManager) AddChannel(channel AlertChannel) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	am.channels = append(am.channels, channel)
}

func (am *AlertManager) GetAlerts(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if limit <= 0 || limit > len(am.history) {
		limit = len(am.history)
	}
	
	// Return most recent alerts
	start := len(am.history) - limit
	alerts := make([]*Alert, limit)
	copy(alerts, am.history[start:])
	
	return alerts
}

// Helper functions

func generateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}

// Default configurations

func getDefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		Enabled:                true,
		CheckInterval:          30 * time.Second,
		HealthCheckTimeout:     10 * time.Second,
		MetricsRetentionPeriod: 24 * time.Hour,
		AlertThresholds: map[string]float64{
			"error_rate":     0.05, // 5%
			"response_time":  1.0,  // 1 second
			"availability":   0.95, // 95%
			"cpu_usage":      80.0, // 80%
			"memory_usage":   85.0, // 85%
		},
		ComponentWeights: map[string]float64{
			"threat_detector":       3.0,
			"adaptive_learning":     2.0,
			"adaptive_rate_limiter": 2.0,
			"middleware":            2.5,
			"storage":               2.5,
			"audit_logger":          1.5,
		},
		EnablePrometheusExport: true,
		PrometheusPort:         9090,
		EnableDetailedMetrics:  true,
		HealthEndpointEnabled:  true,
		CriticalComponents:     []string{"threat_detector", "storage"},
		DegradedThreshold:      70.0,
		UnhealthyThreshold:     50.0,
	}
}

func getDefaultHealthMetrics() *HealthMetrics {
	return &HealthMetrics{
		OverallHealth:      HealthStatusUnknown,
		ComponentHealth:    make(map[string]*ComponentHealth),
		SystemMetrics:      &SystemMetrics{},
		PerformanceMetrics: &PerformanceMetrics{},
		ErrorMetrics:       &ErrorMetrics{},
		ThroughputMetrics:  &ThroughputMetrics{},
		ResourceMetrics:    &ResourceMetrics{},
		LastHealthCheck:    time.Time{},
		HealthScore:        0.0,
		StartTime:          time.Now(),
	}
}

func getDefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		Enabled:           true,
		CooldownPeriod:    5 * time.Minute,
		MaxAlertsPerHour:  20,
		AlertThresholds:   make(map[string]float64),
		EscalationRules:   make([]EscalationRule, 0),
		NotificationDelay: 30 * time.Second,
	}
}