package ai

import (
	"net"
	"time"
)

// ThreatType defines different types of threats
type ThreatType string

const (
	ThreatTypeMalware          ThreatType = "malware"
	ThreatTypePhishing         ThreatType = "phishing"
	ThreatTypeBotnet           ThreatType = "botnet"
	ThreatTypeDataExfiltration ThreatType = "data_exfiltration"
	ThreatTypeCommandControl   ThreatType = "command_control"
	ThreatTypeAnomalous        ThreatType = "anomalous_behavior"
	ThreatTypeZeroDay          ThreatType = "zero_day"
	ThreatTypeInsiderThreat    ThreatType = "insider_threat"
	ThreatTypeSuspicious       ThreatType = "suspicious"
)

// ThreatLevel defines the severity of a threat
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// ActionType defines recommended actions
type ActionType string

const (
	ActionAllow       ActionType = "allow"
	ActionBlock       ActionType = "block"
	ActionQuarantine  ActionType = "quarantine"
	ActionChallenge   ActionType = "challenge"
	ActionRateLimit   ActionType = "rate_limit"
	ActionMonitor     ActionType = "monitor"
	ActionAlert       ActionType = "alert"
)

// AlertLevel defines alert severity levels
type AlertLevel int

const (
	AlertLevelInfo AlertLevel = iota
	AlertLevelWarning
	AlertLevelError
	AlertLevelCritical
)

// ThreatAnalysisRequest represents a request for threat analysis
type ThreatAnalysisRequest struct {
	RequestID     string                 `json:"request_id"`
	SourceIP      net.IP                 `json:"source_ip"`
	UserID        string                 `json:"user_id,omitempty"`
	OrgID         string                 `json:"org_id,omitempty"`
	URL           string                 `json:"url"`
	Method        string                 `json:"method"`
	Headers       map[string]string      `json:"headers"`
	UserAgent     string                 `json:"user_agent"`
	ContentType   string                 `json:"content_type"`
	ContentLength int64                  `json:"content_length"`
	Body          []byte                 `json:"body,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

// ThreatAnalysisResult contains the result of AI threat analysis
type ThreatAnalysisResult struct {
	RequestID        string             `json:"request_id"`
	IsThreat         bool               `json:"is_threat"`
	ThreatType       ThreatType         `json:"threat_type"`
	ThreatLevel      ThreatLevel        `json:"threat_level"`
	Confidence       float64            `json:"confidence"`
	MLPredictions    []*MLPrediction    `json:"ml_predictions"`
	BehaviorAnalysis *BehaviorAnalysis  `json:"behavior_analysis,omitempty"`
	ThreatPatterns   []*ThreatPattern   `json:"threat_patterns,omitempty"`
	RecommendedAction ActionType        `json:"recommended_action"`
	Reason           string             `json:"reason"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	ProcessingTime   time.Duration      `json:"processing_time"`
	Timestamp        time.Time          `json:"timestamp"`
}

// FeatureVector represents extracted features for ML analysis
type FeatureVector struct {
	// Request features
	URLLength         float64 `json:"url_length"`
	URLEntropy        float64 `json:"url_entropy"`
	DomainAge         float64 `json:"domain_age"`
	SubdomainCount    float64 `json:"subdomain_count"`
	PathDepth         float64 `json:"path_depth"`
	QueryParamCount   float64 `json:"query_param_count"`
	
	// Content features
	ContentLength     float64 `json:"content_length"`
	HeaderCount       float64 `json:"header_count"`
	UserAgentEntropy  float64 `json:"user_agent_entropy"`
	
	// Behavioral features
	RequestFrequency  float64 `json:"request_frequency"`
	TimeOfDay         float64 `json:"time_of_day"`
	DayOfWeek         float64 `json:"day_of_week"`
	SessionDuration   float64 `json:"session_duration"`
	
	// Network features
	IPReputation      float64 `json:"ip_reputation"`
	GeoDistance       float64 `json:"geo_distance"`
	ASNReputation     float64 `json:"asn_reputation"`
	
	// Historical features
	PreviousViolations float64 `json:"previous_violations"`
	AccountAge        float64 `json:"account_age"`
	TrustScore        float64 `json:"trust_score"`
	
	// Additional features
	Features          map[string]float64 `json:"features,omitempty"`
}

// MLPrediction represents a prediction from an ML model
type MLPrediction struct {
	ModelName    string             `json:"model_name"`
	ModelVersion string             `json:"model_version"`
	IsThreat     bool               `json:"is_threat"`
	Confidence   float64            `json:"confidence"`
	ThreatType   ThreatType         `json:"threat_type,omitempty"`
	Features     map[string]float64 `json:"features,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time          `json:"timestamp"`
}

// TrainingExample represents a labeled example for model training
type TrainingExample struct {
	ID           string                 `json:"id"`
	Features     map[string]float64     `json:"features"`
	Label        bool                   `json:"label"` // true = threat, false = benign
	ThreatType   ThreatType             `json:"threat_type,omitempty"`
	Confidence   float64                `json:"confidence"`
	Source       string                 `json:"source"` // human_labeled, automated, feedback
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// BehaviorProfile represents behavioral profile for a user/IP
type BehaviorProfile struct {
	Subject           string                 `json:"subject"` // user_id or IP
	FirstSeen         time.Time              `json:"first_seen"`
	LastSeen          time.Time              `json:"last_seen"`
	RequestCount      int64                  `json:"request_count"`
	AverageFrequency  float64                `json:"average_frequency"`
	CommonUserAgents  []string               `json:"common_user_agents"`
	CommonPaths       []string               `json:"common_paths"`
	TimePatterns      map[int]int64          `json:"time_patterns"` // hour -> count
	GeoLocations      []string               `json:"geo_locations"`
	TrustScore        float64                `json:"trust_score"`
	ViolationCount    int64                  `json:"violation_count"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// BehaviorAnalysis represents the result of behavioral analysis
type BehaviorAnalysis struct {
	Subject         string    `json:"subject"`
	IsAnomalous     bool      `json:"is_anomalous"`
	AnomalyScore    float64   `json:"anomaly_score"`
	AnomalyReasons  []string  `json:"anomaly_reasons"`
	Profile         *BehaviorProfile `json:"profile,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// RequestContext represents context for a request being analyzed
type RequestContext struct {
	SourceIP      net.IP            `json:"source_ip"`
	UserAgent     string            `json:"user_agent"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	ContentLength int64             `json:"content_length"`
	Timestamp     time.Time         `json:"timestamp"`
	SessionID     string            `json:"session_id,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	Country       string            `json:"country,omitempty"`
	ASN           string            `json:"asn,omitempty"`
}

// ThreatPattern represents a known threat pattern
type ThreatPattern struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        ThreatType  `json:"type"`
	Level       ThreatLevel `json:"level"`
	Description string      `json:"description"`
	Indicators  []string    `json:"indicators"`
	Confidence  float64     `json:"confidence"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	Count       int64       `json:"count"`
	Sources     []string    `json:"sources"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatQuery represents a query for threat intelligence
type ThreatQuery struct {
	Type      string                 `json:"type"` // ip, domain, url, hash
	Value     string                 `json:"value"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	Query       *ThreatQuery           `json:"query"`
	IsThreat    bool                   `json:"is_threat"`
	ThreatType  ThreatType             `json:"threat_type,omitempty"`
	Confidence  float64                `json:"confidence"`
	Sources     []string               `json:"sources"`
	Patterns    []*ThreatPattern       `json:"patterns,omitempty"`
	Reputation  *ThreatReputation      `json:"reputation,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ThreatReputation represents reputation information
type ThreatReputation struct {
	Score        float64   `json:"score"`        // 0-100, lower is worse
	Category     string    `json:"category"`     // malicious, suspicious, clean
	Sources      []string  `json:"sources"`      // reputation sources
	LastUpdated  time.Time `json:"last_updated"`
	ThreatTypes  []string  `json:"threat_types,omitempty"`
}

// IPThreatReputation represents IP-specific threat reputation
type IPThreatReputation struct {
	IP           net.IP      `json:"ip"`
	Reputation   *ThreatReputation `json:"reputation"`
	Country      string      `json:"country,omitempty"`
	ASN          string      `json:"asn,omitempty"`
	ISP          string      `json:"isp,omitempty"`
	IsWhitelisted bool       `json:"is_whitelisted"`
	IsBlacklisted bool       `json:"is_blacklisted"`
}

// DomainThreatReputation represents domain-specific threat reputation
type DomainThreatReputation struct {
	Domain       string      `json:"domain"`
	Reputation   *ThreatReputation `json:"reputation"`
	DomainAge    int         `json:"domain_age,omitempty"`
	Registrar    string      `json:"registrar,omitempty"`
	IsWhitelisted bool       `json:"is_whitelisted"`
	IsBlacklisted bool       `json:"is_blacklisted"`
}

// ModelInfo represents information about an ML model
type ModelInfo struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Type         string    `json:"type"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Size         int64     `json:"size"`
	IsActive     bool      `json:"is_active"`
	Metrics      *ModelMetrics `json:"metrics,omitempty"`
}

// ModelMetrics represents performance metrics for an ML model
type ModelMetrics struct {
	Accuracy      float64   `json:"accuracy"`
	Precision     float64   `json:"precision"`
	Recall        float64   `json:"recall"`
	F1Score       float64   `json:"f1_score"`
	TruePositives int64     `json:"true_positives"`
	FalsePositives int64    `json:"false_positives"`
	TrueNegatives int64     `json:"true_negatives"`
	FalseNegatives int64    `json:"false_negatives"`
	LastEvaluated time.Time `json:"last_evaluated"`
}

// ThreatPolicies represents threat detection policies
type ThreatPolicies struct {
	GlobalEnabled        bool                       `json:"global_enabled"`
	ConfidenceThreshold  float64                    `json:"confidence_threshold"`
	ThreatLevelThresholds map[ThreatLevel]float64   `json:"threat_level_thresholds"`
	ActionPolicies       map[ThreatType]ActionType  `json:"action_policies"`
	BehavioralAnalysis   bool                       `json:"behavioral_analysis"`
	MachineLearning      bool                       `json:"machine_learning"`
	ThreatIntelligence   bool                       `json:"threat_intelligence"`
	AlertingEnabled      bool                       `json:"alerting_enabled"`
	AlertThreshold       ThreatLevel                `json:"alert_threshold"`
	UpdatedAt            time.Time                  `json:"updated_at"`
}

// AIThreatStats represents statistics about AI threat detection
type AIThreatStats struct {
	TotalRequests        int64                    `json:"total_requests"`
	ThreatsDetected      int64                    `json:"threats_detected"`
	BlockedRequests      int64                    `json:"blocked_requests"`
	ChallengedRequests   int64                    `json:"challenged_requests"`
	ThreatsByType        map[ThreatType]int64     `json:"threats_by_type"`
	ThreatsByLevel       map[ThreatLevel]int64    `json:"threats_by_level"`
	ActionsTaken         map[ActionType]int64     `json:"actions_taken"`
	AverageConfidence    float64                  `json:"average_confidence"`
	AverageProcessingTime time.Duration           `json:"average_processing_time"`
	ModelAccuracy        map[string]float64       `json:"model_accuracy"`
	LastThreat           *time.Time               `json:"last_threat,omitempty"`
	LastUpdated          time.Time                `json:"last_updated"`
}

// AIHealthStatus represents health status of AI components
type AIHealthStatus struct {
	Overall          string                 `json:"overall"` // healthy, degraded, unhealthy
	Components       map[string]string      `json:"components"`
	ModelStatus      map[string]string      `json:"model_status"`
	LastHealthCheck  time.Time              `json:"last_health_check"`
	Issues           []string               `json:"issues,omitempty"`
	Metrics          map[string]interface{} `json:"metrics,omitempty"`
}

// ThreatAlert represents a threat detection alert
type ThreatAlert struct {
	ID          string      `json:"id"`
	Level       AlertLevel  `json:"level"`
	Title       string      `json:"title"`
	Message     string      `json:"message"`
	ThreatType  ThreatType  `json:"threat_type,omitempty"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	SourceIPs   []string    `json:"source_ips,omitempty"`
	UserIDs     []string    `json:"user_ids,omitempty"`
	Actions     []string    `json:"actions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
	Resolved    bool        `json:"resolved"`
	ResolvedAt  *time.Time  `json:"resolved_at,omitempty"`
}