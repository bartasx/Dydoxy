package ddos

import (
	"net"
	"time"
)

// AttackType defines different types of DDoS attacks
type AttackType string

const (
	AttackTypeVolumetric    AttackType = "volumetric"    // High volume attacks
	AttackTypeProtocol      AttackType = "protocol"      // Protocol exploitation
	AttackTypeApplication   AttackType = "application"   // Application layer attacks
	AttackTypeSlow          AttackType = "slow"          // Slow HTTP attacks
	AttackTypeDistributed   AttackType = "distributed"   // Distributed attacks
	AttackTypeBotnet        AttackType = "botnet"        // Botnet attacks
	AttackTypeAmplification AttackType = "amplification" // DNS/NTP amplification
)

// ThreatLevel defines the severity of a threat
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// AttackPattern represents a detected attack pattern
type AttackPattern struct {
	ID          string      `json:"id"`
	Type        AttackType  `json:"type"`
	Level       ThreatLevel `json:"level"`
	Description string      `json:"description"`
	Indicators  []string    `json:"indicators"`
	Confidence  float64     `json:"confidence"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	Count       int64       `json:"count"`
	Sources     []string    `json:"sources"`
	Targets     []string    `json:"targets"`
}

// AttackEvent represents a single attack event
type AttackEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    net.IP                 `json:"source_ip"`
	TargetIP    net.IP                 `json:"target_ip"`
	Type        AttackType             `json:"type"`
	Level       ThreatLevel            `json:"level"`
	Pattern     *AttackPattern         `json:"pattern,omitempty"`
	Metrics     map[string]interface{} `json:"metrics"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	RequestPath string                 `json:"request_path,omitempty"`
	Method      string                 `json:"method,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Blocked     bool                   `json:"blocked"`
	Action      string                 `json:"action"`
	Reason      string                 `json:"reason"`
}

// TrafficMetrics represents traffic analysis metrics
type TrafficMetrics struct {
	RequestsPerSecond    float64   `json:"requests_per_second"`
	BytesPerSecond       float64   `json:"bytes_per_second"`
	ConnectionsPerSecond float64   `json:"connections_per_second"`
	ErrorRate            float64   `json:"error_rate"`
	AverageResponseTime  float64   `json:"average_response_time"`
	UniqueIPs            int64     `json:"unique_ips"`
	TopUserAgents        []string  `json:"top_user_agents"`
	TopPaths             []string  `json:"top_paths"`
	GeoDistribution      []string  `json:"geo_distribution"`
	Timestamp            time.Time `json:"timestamp"`
}

// IPReputation represents reputation information for an IP
type IPReputation struct {
	IP           net.IP      `json:"ip"`
	Score        float64     `json:"score"`        // 0-100, lower is worse
	Category     string      `json:"category"`     // malicious, suspicious, clean
	Sources      []string    `json:"sources"`      // reputation sources
	LastUpdated  time.Time   `json:"last_updated"`
	IsWhitelisted bool       `json:"is_whitelisted"`
	IsBlacklisted bool       `json:"is_blacklisted"`
	Country      string      `json:"country,omitempty"`
	ASN          string      `json:"asn,omitempty"`
	ISP          string      `json:"isp,omitempty"`
	ThreatTypes  []string    `json:"threat_types,omitempty"`
}

// MitigationAction represents an action taken to mitigate an attack
type MitigationAction struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`        // block, rate_limit, challenge, redirect
	Target      string      `json:"target"`      // IP, subnet, user_agent, etc.
	Duration    time.Duration `json:"duration"`  // how long the action lasts
	Reason      string      `json:"reason"`
	Severity    ThreatLevel `json:"severity"`
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Active      bool        `json:"active"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DDoSConfig represents configuration for DDoS protection
type DDoSConfig struct {
	// Detection thresholds
	RequestsPerSecondThreshold    float64 `json:"requests_per_second_threshold"`
	ConnectionsPerSecondThreshold float64 `json:"connections_per_second_threshold"`
	ErrorRateThreshold            float64 `json:"error_rate_threshold"`
	
	// Time windows for analysis
	ShortTermWindow  time.Duration `json:"short_term_window"`  // 1 minute
	MediumTermWindow time.Duration `json:"medium_term_window"` // 5 minutes
	LongTermWindow   time.Duration `json:"long_term_window"`   // 15 minutes
	
	// Mitigation settings
	AutoMitigationEnabled bool          `json:"auto_mitigation_enabled"`
	BlockDuration         time.Duration `json:"block_duration"`
	ChallengeDuration     time.Duration `json:"challenge_duration"`
	
	// IP reputation
	ReputationEnabled     bool    `json:"reputation_enabled"`
	ReputationThreshold   float64 `json:"reputation_threshold"`
	
	// Geographic filtering
	GeoFilteringEnabled   bool     `json:"geo_filtering_enabled"`
	BlockedCountries      []string `json:"blocked_countries"`
	AllowedCountries      []string `json:"allowed_countries"`
	
	// Rate limiting
	GlobalRateLimit       int64 `json:"global_rate_limit"`
	PerIPRateLimit        int64 `json:"per_ip_rate_limit"`
	
	// Advanced detection
	BehavioralAnalysis    bool `json:"behavioral_analysis"`
	MachineLearning       bool `json:"machine_learning"`
	
	// Logging and alerting
	LogLevel              string `json:"log_level"`
	AlertingEnabled       bool   `json:"alerting_enabled"`
	AlertThreshold        ThreatLevel `json:"alert_threshold"`
}

// DDoSStats represents statistics about DDoS protection
type DDoSStats struct {
	TotalRequests        int64                    `json:"total_requests"`
	BlockedRequests      int64                    `json:"blocked_requests"`
	ChallengedRequests   int64                    `json:"challenged_requests"`
	AttacksDetected      int64                    `json:"attacks_detected"`
	AttacksByType        map[AttackType]int64     `json:"attacks_by_type"`
	AttacksByLevel       map[ThreatLevel]int64    `json:"attacks_by_level"`
	TopAttackSources     []string                 `json:"top_attack_sources"`
	MitigationActions    int64                    `json:"mitigation_actions"`
	AverageResponseTime  float64                  `json:"average_response_time"`
	CurrentThreatLevel   ThreatLevel              `json:"current_threat_level"`
	ActiveMitigations    int64                    `json:"active_mitigations"`
	LastAttack           *time.Time               `json:"last_attack,omitempty"`
	LastUpdated          time.Time                `json:"last_updated"`
}

// DetectionResult represents the result of attack detection
type DetectionResult struct {
	IsAttack     bool           `json:"is_attack"`
	AttackType   AttackType     `json:"attack_type,omitempty"`
	ThreatLevel  ThreatLevel    `json:"threat_level"`
	Confidence   float64        `json:"confidence"`
	Patterns     []AttackPattern `json:"patterns,omitempty"`
	Metrics      *TrafficMetrics `json:"metrics,omitempty"`
	Reason       string         `json:"reason"`
	Timestamp    time.Time      `json:"timestamp"`
}

// MitigationResult represents the result of mitigation
type MitigationResult struct {
	Action       string        `json:"action"`
	Applied      bool          `json:"applied"`
	Duration     time.Duration `json:"duration,omitempty"`
	Reason       string        `json:"reason"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
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

// AlertLevel defines alert severity levels
type AlertLevel int

const (
	AlertLevelInfo AlertLevel = iota
	AlertLevelWarning
	AlertLevelError
	AlertLevelCritical
)

// DDoSAlert represents an alert about DDoS activity
type DDoSAlert struct {
	ID          string      `json:"id"`
	Level       AlertLevel  `json:"level"`
	Title       string      `json:"title"`
	Message     string      `json:"message"`
	AttackType  AttackType  `json:"attack_type,omitempty"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	SourceIPs   []string    `json:"source_ips,omitempty"`
	Metrics     *TrafficMetrics `json:"metrics,omitempty"`
	Actions     []string    `json:"actions,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
	Resolved    bool        `json:"resolved"`
	ResolvedAt  *time.Time  `json:"resolved_at,omitempty"`
}