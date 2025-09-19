package ai

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// AISecurityMiddleware provides AI-powered threat detection for HTTP requests
type AISecurityMiddleware struct {
	threatDetector    AIThreatDetector
	config           *MiddlewareConfig
	logger           *logrus.Logger
	stats            *MiddlewareStats
}

// MiddlewareConfig holds configuration for AI security middleware
type MiddlewareConfig struct {
	Enabled                bool                   `json:"enabled"`
	ThreatThreshold        float64               `json:"threat_threshold"`
	BlockingEnabled        bool                  `json:"blocking_enabled"`
	ChallengeEnabled       bool                  `json:"challenge_enabled"`
	LoggingEnabled         bool                  `json:"logging_enabled"`
	ResponseActions        map[ThreatLevel]string `json:"response_actions"`
	WhitelistedPaths       []string              `json:"whitelisted_paths"`
	WhitelistedIPs         []string              `json:"whitelisted_ips"`
	MaxRequestSize         int64                 `json:"max_request_size"`
	AnalysisTimeout        time.Duration         `json:"analysis_timeout"`
	EnableBehavioralCheck  bool                  `json:"enable_behavioral_check"`
	EnableContentAnalysis  bool                  `json:"enable_content_analysis"`
	EnableThreatIntel      bool                  `json:"enable_threat_intel"`
}

// MiddlewareStats tracks middleware performance and statistics
type MiddlewareStats struct {
	RequestsProcessed    int64                    `json:"requests_processed"`
	ThreatsDetected      int64                    `json:"threats_detected"`
	RequestsBlocked      int64                    `json:"requests_blocked"`
	RequestsChallenged   int64                    `json:"requests_challenged"`
	AverageAnalysisTime  time.Duration            `json:"average_analysis_time"`
	ThreatsByLevel       map[ThreatLevel]int64    `json:"threats_by_level"`
	ThreatsByType        map[ThreatType]int64     `json:"threats_by_type"`
	ResponseActionCounts map[string]int64         `json:"response_action_counts"`
	LastUpdated          time.Time                `json:"last_updated"`
}

// ResponseAction defines possible actions for threat responses
type ResponseAction string

const (
	ActionAllow     ResponseAction = "allow"
	ActionBlock     ResponseAction = "block"
	ActionChallenge ResponseAction = "challenge"
	ActionRateLimit ResponseAction = "rate_limit"
	ActionLog       ResponseAction = "log"
)

// NewAISecurityMiddleware creates a new AI security middleware
func NewAISecurityMiddleware(threatDetector AIThreatDetector, logger *logrus.Logger) *AISecurityMiddleware {
	return &AISecurityMiddleware{
		threatDetector: threatDetector,
		config:        getDefaultMiddlewareConfig(),
		logger:        logger,
		stats:         getDefaultMiddlewareStats(),
	}
}

// Handler returns the Gin middleware handler function
func (m *AISecurityMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.Enabled {
			c.Next()
			return
		}

		startTime := time.Now()
		
		// Check if path is whitelisted
		if m.isPathWhitelisted(c.Request.URL.Path) {
			c.Next()
			return
		}
		
		// Check if IP is whitelisted
		clientIP := c.ClientIP()
		if m.isIPWhitelisted(clientIP) {
			c.Next()
			return
		}
		
		// Create threat analysis request
		analysisRequest := m.createThreatAnalysisRequest(c)
		
		// Perform threat analysis with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.AnalysisTimeout)
		defer cancel()
		
		result, err := m.threatDetector.AnalyzeRequest(ctx, analysisRequest)
		if err != nil {
			m.logger.Errorf("Threat analysis failed: %v", err)
			// On analysis failure, allow request but log the error
			c.Next()
			return
		}
		
		analysisTime := time.Since(startTime)
		
		// Update statistics
		m.updateStats(result, analysisTime)
		
		// Log threat analysis result
		if m.config.LoggingEnabled {
			m.logThreatAnalysis(c, result, analysisTime)
		}
		
		// Determine response action
		action := m.determineResponseAction(result)
		
		// Execute response action
		if m.executeResponseAction(c, action, result) {
			return // Request was blocked or challenged
		}
		
		// Add threat information to context for downstream middleware
		m.addThreatInfoToContext(c, result)
		
		c.Next()
	}
}

// createThreatAnalysisRequest creates a threat analysis request from Gin context
func (m *AISecurityMiddleware) createThreatAnalysisRequest(c *gin.Context) *ThreatAnalysisRequest {
	// Read request body if needed for content analysis
	var body []byte
	if m.config.EnableContentAnalysis && c.Request.ContentLength > 0 && c.Request.ContentLength <= m.config.MaxRequestSize {
		if bodyBytes, err := c.GetRawData(); err == nil {
			body = bodyBytes
			// Restore body for downstream handlers
			c.Request.Body = http.NoBody
		}
	}
	
	return &ThreatAnalysisRequest{
		RequestID: generateRequestID(c),
		Timestamp: time.Now(),
		ClientIP:  c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Method:    c.Request.Method,
		URL:       c.Request.URL.String(),
		Headers:   convertHeaders(c.Request.Header),
		Body:      body,
		UserID:    m.extractUserID(c),
		SessionID: m.extractSessionID(c),
		Metadata: map[string]interface{}{
			"content_length": c.Request.ContentLength,
			"content_type":   c.GetHeader("Content-Type"),
			"referer":        c.GetHeader("Referer"),
			"origin":         c.GetHeader("Origin"),
			"x_forwarded_for": c.GetHeader("X-Forwarded-For"),
		},
	}
}

// determineResponseAction determines the appropriate response action based on threat analysis
func (m *AISecurityMiddleware) determineResponseAction(result *ThreatAnalysisResult) ResponseAction {
	if !result.IsThreat {
		return ActionAllow
	}
	
	// Check if we have a configured action for this threat level
	if actionStr, exists := m.config.ResponseActions[result.ThreatLevel]; exists {
		return ResponseAction(actionStr)
	}
	
	// Default actions based on threat level
	switch result.ThreatLevel {
	case ThreatLevelCritical:
		return ActionBlock
	case ThreatLevelHigh:
		if m.config.BlockingEnabled {
			return ActionBlock
		}
		return ActionChallenge
	case ThreatLevelMedium:
		if m.config.ChallengeEnabled {
			return ActionChallenge
		}
		return ActionRateLimit
	case ThreatLevelLow:
		return ActionLog
	default:
		return ActionAllow
	}
}

// executeResponseAction executes the determined response action
func (m *AISecurityMiddleware) executeResponseAction(c *gin.Context, action ResponseAction, result *ThreatAnalysisResult) bool {
	switch action {
	case ActionBlock:
		m.blockRequest(c, result)
		m.stats.RequestsBlocked++
		return true
		
	case ActionChallenge:
		m.challengeRequest(c, result)
		m.stats.RequestsChallenged++
		return true
		
	case ActionRateLimit:
		// Rate limiting is handled by separate middleware
		// Just add headers to indicate rate limiting should be applied
		c.Header("X-AI-Rate-Limit", "true")
		c.Header("X-AI-Threat-Level", string(result.ThreatLevel))
		
	case ActionLog:
		// Logging is already handled, just continue
		
	case ActionAllow:
		// Continue processing
	}
	
	// Update action statistics
	m.stats.ResponseActionCounts[string(action)]++
	
	return false
}

// blockRequest blocks the request with appropriate response
func (m *AISecurityMiddleware) blockRequest(c *gin.Context, result *ThreatAnalysisResult) {
	response := gin.H{
		"error":       "Request blocked by security system",
		"threat_type": result.ThreatType,
		"request_id":  result.RequestID,
		"timestamp":   result.Timestamp,
	}
	
	// Add additional context for debugging (in development mode)
	if gin.Mode() == gin.DebugMode {
		response["threat_level"] = result.ThreatLevel
		response["confidence"] = result.Confidence
		response["reasons"] = result.Reasons
	}
	
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.JSON(http.StatusForbidden, response)
	c.Abort()
}

// challengeRequest presents a challenge to the user
func (m *AISecurityMiddleware) challengeRequest(c *gin.Context, result *ThreatAnalysisResult) {
	// Simple challenge implementation - in practice, you might use CAPTCHA or other methods
	challengeToken := generateChallengeToken(c, result)
	
	response := gin.H{
		"challenge_required": true,
		"challenge_token":    challengeToken,
		"message":           "Please complete the security challenge to continue",
		"request_id":        result.RequestID,
	}
	
	c.Header("X-Challenge-Required", "true")
	c.Header("X-Challenge-Token", challengeToken)
	c.JSON(http.StatusUnauthorized, response)
	c.Abort()
}

// Helper methods

func (m *AISecurityMiddleware) isPathWhitelisted(path string) bool {
	for _, whitelistedPath := range m.config.WhitelistedPaths {
		if strings.HasPrefix(path, whitelistedPath) {
			return true
		}
	}
	return false
}

func (m *AISecurityMiddleware) isIPWhitelisted(ip string) bool {
	for _, whitelistedIP := range m.config.WhitelistedIPs {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

func (m *AISecurityMiddleware) extractUserID(c *gin.Context) string {
	// Try to extract user ID from various sources
	if userID := c.GetHeader("X-User-ID"); userID != "" {
		return userID
	}
	if userID := c.GetString("user_id"); userID != "" {
		return userID
	}
	// Could also check JWT claims, session data, etc.
	return ""
}

func (m *AISecurityMiddleware) extractSessionID(c *gin.Context) string {
	// Try to extract session ID from various sources
	if sessionID := c.GetHeader("X-Session-ID"); sessionID != "" {
		return sessionID
	}
	if cookie, err := c.Cookie("session_id"); err == nil {
		return cookie
	}
	return ""
}

func (m *AISecurityMiddleware) updateStats(result *ThreatAnalysisResult, analysisTime time.Duration) {
	m.stats.RequestsProcessed++
	
	if result.IsThreat {
		m.stats.ThreatsDetected++
		m.stats.ThreatsByLevel[result.ThreatLevel]++
		m.stats.ThreatsByType[result.ThreatType]++
	}
	
	// Update average analysis time (simple moving average)
	if m.stats.RequestsProcessed == 1 {
		m.stats.AverageAnalysisTime = analysisTime
	} else {
		// Exponential moving average with alpha = 0.1
		alpha := 0.1
		m.stats.AverageAnalysisTime = time.Duration(
			float64(m.stats.AverageAnalysisTime)*(1-alpha) + float64(analysisTime)*alpha,
		)
	}
	
	m.stats.LastUpdated = time.Now()
}

func (m *AISecurityMiddleware) logThreatAnalysis(c *gin.Context, result *ThreatAnalysisResult, analysisTime time.Duration) {
	fields := logrus.Fields{
		"request_id":     result.RequestID,
		"client_ip":      c.ClientIP(),
		"method":         c.Request.Method,
		"url":            c.Request.URL.String(),
		"user_agent":     c.GetHeader("User-Agent"),
		"is_threat":      result.IsThreat,
		"analysis_time":  analysisTime,
	}
	
	if result.IsThreat {
		fields["threat_type"] = result.ThreatType
		fields["threat_level"] = result.ThreatLevel
		fields["confidence"] = result.Confidence
		fields["reasons"] = result.Reasons
		
		m.logger.WithFields(fields).Warn("Threat detected")
	} else {
		m.logger.WithFields(fields).Debug("Request analyzed - no threat detected")
	}
}

func (m *AISecurityMiddleware) addThreatInfoToContext(c *gin.Context, result *ThreatAnalysisResult) {
	c.Set("ai_threat_analysis", result)
	c.Header("X-AI-Analysis-ID", result.RequestID)
	c.Header("X-AI-Threat-Score", fmt.Sprintf("%.3f", result.Confidence))
	
	if result.IsThreat {
		c.Header("X-AI-Threat-Detected", "true")
		c.Header("X-AI-Threat-Level", string(result.ThreatLevel))
		c.Header("X-AI-Threat-Type", string(result.ThreatType))
	}
}

// Utility functions

func generateRequestID(c *gin.Context) string {
	// Generate a unique request ID
	timestamp := time.Now().UnixNano()
	clientIP := strings.ReplaceAll(c.ClientIP(), ".", "")
	return fmt.Sprintf("req-%d-%s", timestamp, clientIP)
}

func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0] // Take first value
		}
	}
	return result
}

func generateChallengeToken(c *gin.Context, result *ThreatAnalysisResult) string {
	// Simple challenge token generation - in practice, use proper cryptographic methods
	timestamp := time.Now().Unix()
	clientIP := c.ClientIP()
	return fmt.Sprintf("challenge-%s-%d-%s", result.RequestID, timestamp, clientIP)
}

// Configuration and statistics methods

func (m *AISecurityMiddleware) SetConfig(config *MiddlewareConfig) {
	m.config = config
	m.logger.Info("Updated AI security middleware configuration")
}

func (m *AISecurityMiddleware) GetConfig() *MiddlewareConfig {
	configCopy := *m.config
	return &configCopy
}

func (m *AISecurityMiddleware) GetStats() *MiddlewareStats {
	statsCopy := *m.stats
	
	// Deep copy maps
	statsCopy.ThreatsByLevel = make(map[ThreatLevel]int64)
	for k, v := range m.stats.ThreatsByLevel {
		statsCopy.ThreatsByLevel[k] = v
	}
	
	statsCopy.ThreatsByType = make(map[ThreatType]int64)
	for k, v := range m.stats.ThreatsByType {
		statsCopy.ThreatsByType[k] = v
	}
	
	statsCopy.ResponseActionCounts = make(map[string]int64)
	for k, v := range m.stats.ResponseActionCounts {
		statsCopy.ResponseActionCounts[k] = v
	}
	
	return &statsCopy
}

func (m *AISecurityMiddleware) ResetStats() {
	m.stats = getDefaultMiddlewareStats()
	m.logger.Info("Reset AI security middleware statistics")
}

// Default configurations

func getDefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		Enabled:               true,
		ThreatThreshold:       0.7,
		BlockingEnabled:       true,
		ChallengeEnabled:      true,
		LoggingEnabled:        true,
		ResponseActions: map[ThreatLevel]string{
			ThreatLevelCritical: string(ActionBlock),
			ThreatLevelHigh:     string(ActionBlock),
			ThreatLevelMedium:   string(ActionChallenge),
			ThreatLevelLow:      string(ActionLog),
		},
		WhitelistedPaths:      []string{"/health", "/metrics", "/favicon.ico"},
		WhitelistedIPs:        []string{"127.0.0.1", "::1"},
		MaxRequestSize:        1024 * 1024, // 1MB
		AnalysisTimeout:       5 * time.Second,
		EnableBehavioralCheck: true,
		EnableContentAnalysis: true,
		EnableThreatIntel:     true,
	}
}

func getDefaultMiddlewareStats() *MiddlewareStats {
	return &MiddlewareStats{
		ThreatsByLevel:       make(map[ThreatLevel]int64),
		ThreatsByType:        make(map[ThreatType]int64),
		ResponseActionCounts: make(map[string]int64),
		LastUpdated:          time.Now(),
	}
}