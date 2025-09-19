package ddos

import (
	"context"
	"net"
	"time"
)

// DDoSProtector defines the main interface for DDoS protection
type DDoSProtector interface {
	// AnalyzeRequest analyzes a request for potential DDoS patterns
	AnalyzeRequest(ctx context.Context, request *RequestContext) (*DetectionResult, error)
	
	// ApplyMitigation applies mitigation measures for detected attacks
	ApplyMitigation(ctx context.Context, result *DetectionResult, request *RequestContext) (*MitigationResult, error)
	
	// UpdateConfig updates the DDoS protection configuration
	UpdateConfig(ctx context.Context, config *DDoSConfig) error
	
	// GetConfig returns the current configuration
	GetConfig(ctx context.Context) (*DDoSConfig, error)
	
	// GetStats returns current DDoS protection statistics
	GetStats(ctx context.Context) (*DDoSStats, error)
	
	// GetActiveAttacks returns currently active attacks
	GetActiveAttacks(ctx context.Context) ([]*AttackEvent, error)
	
	// GetActiveMitigations returns currently active mitigations
	GetActiveMitigations(ctx context.Context) ([]*MitigationAction, error)
	
	// ResetStats resets statistics counters
	ResetStats(ctx context.Context) error
}

// AttackDetector defines the interface for attack detection
type AttackDetector interface {
	// DetectAttack analyzes traffic patterns to detect attacks
	DetectAttack(ctx context.Context, metrics *TrafficMetrics, request *RequestContext) (*DetectionResult, error)
	
	// UpdatePatterns updates known attack patterns
	UpdatePatterns(ctx context.Context, patterns []*AttackPattern) error
	
	// GetPatterns returns known attack patterns
	GetPatterns(ctx context.Context) ([]*AttackPattern, error)
	
	// TrainModel trains the detection model with new data
	TrainModel(ctx context.Context, events []*AttackEvent) error
}

// MitigationEngine defines the interface for attack mitigation
type MitigationEngine interface {
	// CreateMitigation creates a new mitigation action
	CreateMitigation(ctx context.Context, action *MitigationAction) error
	
	// RemoveMitigation removes an existing mitigation action
	RemoveMitigation(ctx context.Context, actionID string) error
	
	// UpdateMitigation updates an existing mitigation action
	UpdateMitigation(ctx context.Context, action *MitigationAction) error
	
	// GetMitigation retrieves a specific mitigation action
	GetMitigation(ctx context.Context, actionID string) (*MitigationAction, error)
	
	// ListMitigations lists all active mitigations
	ListMitigations(ctx context.Context) ([]*MitigationAction, error)
	
	// CleanupExpired removes expired mitigation actions
	CleanupExpired(ctx context.Context) (int64, error)
}

// TrafficAnalyzer defines the interface for traffic analysis
type TrafficAnalyzer interface {
	// AnalyzeTraffic analyzes current traffic patterns
	AnalyzeTraffic(ctx context.Context, window time.Duration) (*TrafficMetrics, error)
	
	// RecordRequest records a request for analysis
	RecordRequest(ctx context.Context, request *RequestContext) error
	
	// GetMetrics returns traffic metrics for a specific time window
	GetMetrics(ctx context.Context, start, end time.Time) ([]*TrafficMetrics, error)
	
	// GetTopIPs returns top IPs by request count
	GetTopIPs(ctx context.Context, limit int, window time.Duration) ([]string, error)
	
	// GetAnomalies detects traffic anomalies
	GetAnomalies(ctx context.Context, window time.Duration) ([]*TrafficMetrics, error)
}

// ReputationService defines the interface for IP reputation checking
type ReputationService interface {
	// GetReputation gets reputation information for an IP
	GetReputation(ctx context.Context, ip net.IP) (*IPReputation, error)
	
	// UpdateReputation updates reputation information for an IP
	UpdateReputation(ctx context.Context, reputation *IPReputation) error
	
	// IsBlacklisted checks if an IP is blacklisted
	IsBlacklisted(ctx context.Context, ip net.IP) (bool, error)
	
	// IsWhitelisted checks if an IP is whitelisted
	IsWhitelisted(ctx context.Context, ip net.IP) (bool, error)
	
	// AddToBlacklist adds an IP to the blacklist
	AddToBlacklist(ctx context.Context, ip net.IP, reason string, duration time.Duration) error
	
	// AddToWhitelist adds an IP to the whitelist
	AddToWhitelist(ctx context.Context, ip net.IP, reason string) error
	
	// RemoveFromBlacklist removes an IP from the blacklist
	RemoveFromBlacklist(ctx context.Context, ip net.IP) error
	
	// RemoveFromWhitelist removes an IP from the whitelist
	RemoveFromWhitelist(ctx context.Context, ip net.IP) error
	
	// SyncWithFeeds synchronizes with external reputation feeds
	SyncWithFeeds(ctx context.Context) error
}

// GeoFilter defines the interface for geographic filtering
type GeoFilter interface {
	// GetCountry gets the country for an IP address
	GetCountry(ctx context.Context, ip net.IP) (string, error)
	
	// IsBlocked checks if a country is blocked
	IsBlocked(ctx context.Context, country string) (bool, error)
	
	// IsAllowed checks if a country is explicitly allowed
	IsAllowed(ctx context.Context, country string) (bool, error)
	
	// UpdateBlockedCountries updates the list of blocked countries
	UpdateBlockedCountries(ctx context.Context, countries []string) error
	
	// UpdateAllowedCountries updates the list of allowed countries
	UpdateAllowedCountries(ctx context.Context, countries []string) error
	
	// GetBlockedCountries returns the list of blocked countries
	GetBlockedCountries(ctx context.Context) ([]string, error)
	
	// GetAllowedCountries returns the list of allowed countries
	GetAllowedCountries(ctx context.Context) ([]string, error)
}

// AlertManager defines the interface for alert management
type AlertManager interface {
	// CreateAlert creates a new DDoS alert
	CreateAlert(ctx context.Context, alert *DDoSAlert) error
	
	// GetAlerts retrieves alerts based on criteria
	GetAlerts(ctx context.Context, level AlertLevel, resolved bool, limit int) ([]*DDoSAlert, error)
	
	// ResolveAlert marks an alert as resolved
	ResolveAlert(ctx context.Context, alertID string) error
	
	// SendAlert sends an alert through configured channels
	SendAlert(ctx context.Context, alert *DDoSAlert) error
	
	// GetUnresolvedAlerts returns all unresolved alerts
	GetUnresolvedAlerts(ctx context.Context) ([]*DDoSAlert, error)
}

// DDoSStorage defines the interface for DDoS data persistence
type DDoSStorage interface {
	// Attack events
	SaveAttackEvent(ctx context.Context, event *AttackEvent) error
	LoadAttackEvent(ctx context.Context, eventID string) (*AttackEvent, error)
	ListAttackEvents(ctx context.Context, start, end time.Time, limit int) ([]*AttackEvent, error)
	
	// Attack patterns
	SaveAttackPattern(ctx context.Context, pattern *AttackPattern) error
	LoadAttackPattern(ctx context.Context, patternID string) (*AttackPattern, error)
	ListAttackPatterns(ctx context.Context) ([]*AttackPattern, error)
	
	// Mitigation actions
	SaveMitigationAction(ctx context.Context, action *MitigationAction) error
	LoadMitigationAction(ctx context.Context, actionID string) (*MitigationAction, error)
	ListMitigationActions(ctx context.Context, active bool) ([]*MitigationAction, error)
	DeleteMitigationAction(ctx context.Context, actionID string) error
	
	// Traffic metrics
	SaveTrafficMetrics(ctx context.Context, metrics *TrafficMetrics) error
	LoadTrafficMetrics(ctx context.Context, start, end time.Time) ([]*TrafficMetrics, error)
	
	// IP reputation
	SaveIPReputation(ctx context.Context, reputation *IPReputation) error
	LoadIPReputation(ctx context.Context, ip net.IP) (*IPReputation, error)
	
	// Alerts
	SaveAlert(ctx context.Context, alert *DDoSAlert) error
	LoadAlert(ctx context.Context, alertID string) (*DDoSAlert, error)
	ListAlerts(ctx context.Context, level AlertLevel, resolved bool, limit int) ([]*DDoSAlert, error)
	
	// Statistics
	GetStats(ctx context.Context) (*DDoSStats, error)
	UpdateStats(ctx context.Context, stats *DDoSStats) error
	
	// Configuration
	SaveConfig(ctx context.Context, config *DDoSConfig) error
	LoadConfig(ctx context.Context) (*DDoSConfig, error)
	
	// Cleanup
	CleanupOldData(ctx context.Context, olderThan time.Time) (int64, error)
}

// BehavioralAnalyzer defines the interface for behavioral analysis
type BehavioralAnalyzer interface {
	// AnalyzeBehavior analyzes user/IP behavior patterns
	AnalyzeBehavior(ctx context.Context, ip net.IP, requests []*RequestContext) (*DetectionResult, error)
	
	// UpdateProfile updates behavioral profile for an IP
	UpdateProfile(ctx context.Context, ip net.IP, request *RequestContext) error
	
	// GetProfile gets behavioral profile for an IP
	GetProfile(ctx context.Context, ip net.IP) (map[string]interface{}, error)
	
	// DetectAnomalies detects behavioral anomalies
	DetectAnomalies(ctx context.Context, ip net.IP, request *RequestContext) (bool, float64, error)
	
	// TrainModel trains the behavioral analysis model
	TrainModel(ctx context.Context, data []*RequestContext) error
}

// MLDetector defines the interface for machine learning-based detection
type MLDetector interface {
	// Predict predicts if a request is part of an attack
	Predict(ctx context.Context, features map[string]float64) (bool, float64, error)
	
	// Train trains the ML model with labeled data
	Train(ctx context.Context, features []map[string]float64, labels []bool) error
	
	// UpdateModel updates the model with new data
	UpdateModel(ctx context.Context, features map[string]float64, label bool) error
	
	// GetModelInfo returns information about the current model
	GetModelInfo(ctx context.Context) (map[string]interface{}, error)
	
	// ExtractFeatures extracts features from a request context
	ExtractFeatures(ctx context.Context, request *RequestContext, metrics *TrafficMetrics) (map[string]float64, error)
}