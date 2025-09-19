package ai

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"../../ratelimit"
)

// AIAdaptiveRateLimiter implements threat-based adaptive rate limiting
type AIAdaptiveRateLimiter struct {
	threatDetector    AIThreatDetector
	multiLayerLimiter *ratelimit.MultiLayerRateLimiter
	bucketManager     *ratelimit.TokenBucketManager
	userOrgManager    *ratelimit.UserOrgLimitManager
	config           *AdaptiveRateLimitConfig
	stats            *AdaptiveRateLimitStats
	threatCache      map[string]*CachedThreatInfo
	logger           *logrus.Logger
	mu               sync.RWMutex
}

// AdaptiveRateLimitConfig holds configuration for AI-adaptive rate limiting
type AdaptiveRateLimitConfig struct {
	Enabled                    bool                           `json:"enabled"`
	ThreatBasedAdjustment      bool                           `json:"threat_based_adjustment"`
	BehavioralAdjustment       bool                           `json:"behavioral_adjustment"`
	ThreatMultipliers          map[ThreatLevel]float64        `json:"threat_multipliers"`
	ThreatTypeMultipliers      map[ThreatType]float64         `json:"threat_type_multipliers"`
	MinRateLimitMultiplier     float64                        `json:"min_rate_limit_multiplier"`
	MaxRateLimitMultiplier     float64                        `json:"max_rate_limit_multiplier"`
	ThreatCacheTimeout         time.Duration                  `json:"threat_cache_timeout"`
	AdaptationSensitivity      float64                        `json:"adaptation_sensitivity"`
	GracePeriod                time.Duration                  `json:"grace_period"`
	EmergencyMode              bool                           `json:"emergency_mode"`
	EmergencyThreshold         float64                        `json:"emergency_threshold"`
	EmergencyMultiplier        float64                        `json:"emergency_multiplier"`
	WhitelistedUsers           []string                       `json:"whitelisted_users"`
	WhitelistedIPs             []string                       `json:"whitelisted_ips"`
	EnableProgressivePenalty   bool                           `json:"enable_progressive_penalty"`
	ProgressivePenaltyFactor   float64                        `json:"progressive_penalty_factor"`
	ReputationDecayRate        float64                        `json:"reputation_decay_rate"`
}

// AdaptiveRateLimitStats tracks adaptive rate limiting statistics
type AdaptiveRateLimitStats struct {
	RequestsProcessed          int64                          `json:"requests_processed"`
	ThreatBasedAdjustments     int64                          `json:"threat_based_adjustments"`
	BehavioralAdjustments      int64                          `json:"behavioral_adjustments"`
	EmergencyModeActivations   int64                          `json:"emergency_mode_activations"`
	AdjustmentsByThreatLevel   map[ThreatLevel]int64          `json:"adjustments_by_threat_level"`
	AdjustmentsByThreatType    map[ThreatType]int64           `json:"adjustments_by_threat_type"`
	AverageMultiplier          float64                        `json:"average_multiplier"`
	CacheHitRate               float64                        `json:"cache_hit_rate"`
	CacheSize                  int                            `json:"cache_size"`
	LastEmergencyMode          time.Time                      `json:"last_emergency_mode"`
	LastUpdated                time.Time                      `json:"last_updated"`
}

// CachedThreatInfo represents cached threat analysis information
type CachedThreatInfo struct {
	ThreatAnalysis    *ThreatAnalysisResult `json:"threat_analysis"`
	Multiplier        float64               `json:"multiplier"`
	ReputationScore   float64               `json:"reputation_score"`
	ViolationCount    int64                 `json:"violation_count"`
	LastViolation     time.Time             `json:"last_violation"`
	CachedAt          time.Time             `json:"cached_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
}

// AdaptiveRateLimitRequest extends the standard rate limit request with AI context
type AdaptiveRateLimitRequest struct {
	*ratelimit.RateLimitRequest
	ThreatAnalysis    *ThreatAnalysisResult `json:"threat_analysis,omitempty"`
	ReputationScore   float64               `json:"reputation_score,omitempty"`
	BypassAI          bool                  `json:"bypass_ai,omitempty"`
}

// AdaptiveRateLimitResult extends the standard result with AI information
type AdaptiveRateLimitResult struct {
	*ratelimit.MultiLayerResult
	ThreatAnalysis      *ThreatAnalysisResult `json:"threat_analysis,omitempty"`
	AppliedMultiplier   float64               `json:"applied_multiplier"`
	AdjustmentReason    string                `json:"adjustment_reason"`
	ReputationScore     float64               `json:"reputation_score"`
	EmergencyMode       bool                  `json:"emergency_mode"`
	CacheHit            bool                  `json:"cache_hit"`
}

// NewAIAdaptiveRateLimiter creates a new AI-adaptive rate limiter
func NewAIAdaptiveRateLimiter(
	threatDetector AIThreatDetector,
	multiLayerLimiter *ratelimit.MultiLayerRateLimiter,
	bucketManager *ratelimit.TokenBucketManager,
	userOrgManager *ratelimit.UserOrgLimitManager,
	logger *logrus.Logger,
) *AIAdaptiveRateLimiter {
	return &AIAdaptiveRateLimiter{
		threatDetector:    threatDetector,
		multiLayerLimiter: multiLayerLimiter,
		bucketManager:     bucketManager,
		userOrgManager:    userOrgManager,
		config:           getDefaultAdaptiveRateLimitConfig(),
		stats:            getDefaultAdaptiveRateLimitStats(),
		threatCache:      make(map[string]*CachedThreatInfo),
		logger:           logger,
	}
}

// CheckAdaptiveRateLimit performs AI-enhanced rate limiting
func (arl *AIAdaptiveRateLimiter) CheckAdaptiveRateLimit(ctx context.Context, request *AdaptiveRateLimitRequest) (*AdaptiveRateLimitResult, error) {
	if !arl.config.Enabled {
		// Fall back to standard rate limiting
		standardResult, err := arl.multiLayerLimiter.CheckRateLimit(ctx, request.RateLimitRequest)
		if err != nil {
			return nil, err
		}
		
		return &AdaptiveRateLimitResult{
			MultiLayerResult:  standardResult,
			AppliedMultiplier: 1.0,
			AdjustmentReason:  "ai_disabled",
		}, nil
	}
	
	arl.mu.Lock()
	arl.stats.RequestsProcessed++
	arl.mu.Unlock()
	
	// Check if user/IP is whitelisted
	if arl.isWhitelisted(request) {
		standardResult, err := arl.multiLayerLimiter.CheckRateLimit(ctx, request.RateLimitRequest)
		if err != nil {
			return nil, err
		}
		
		return &AdaptiveRateLimitResult{
			MultiLayerResult:  standardResult,
			AppliedMultiplier: 1.0,
			AdjustmentReason:  "whitelisted",
		}, nil
	}
	
	// Get or perform threat analysis
	threatInfo, cacheHit, err := arl.getThreatInfo(ctx, request)
	if err != nil {
		arl.logger.Errorf("Failed to get threat info: %v", err)
		// Fall back to standard rate limiting on error
		standardResult, err := arl.multiLayerLimiter.CheckRateLimit(ctx, request.RateLimitRequest)
		if err != nil {
			return nil, err
		}
		
		return &AdaptiveRateLimitResult{
			MultiLayerResult:  standardResult,
			AppliedMultiplier: 1.0,
			AdjustmentReason:  "threat_analysis_failed",
		}, nil
	}
	
	// Calculate adaptive multiplier
	multiplier, reason := arl.calculateAdaptiveMultiplier(threatInfo)
	
	// Apply adaptive rate limiting
	adaptedRequest := arl.applyAdaptiveMultiplier(request.RateLimitRequest, multiplier)
	
	// Perform rate limiting with adapted parameters
	standardResult, err := arl.multiLayerLimiter.CheckRateLimit(ctx, adaptedRequest)
	if err != nil {
		return nil, err
	}
	
	// Update statistics
	arl.updateStats(threatInfo.ThreatAnalysis, multiplier, cacheHit)
	
	// Update threat cache with violation information
	if !standardResult.Allowed {
		arl.updateThreatCacheOnViolation(request, threatInfo)
	}
	
	result := &AdaptiveRateLimitResult{
		MultiLayerResult:    standardResult,
		ThreatAnalysis:      threatInfo.ThreatAnalysis,
		AppliedMultiplier:   multiplier,
		AdjustmentReason:    reason,
		ReputationScore:     threatInfo.ReputationScore,
		EmergencyMode:       arl.config.EmergencyMode,
		CacheHit:            cacheHit,
	}
	
	return result, nil
}

// getThreatInfo gets threat information from cache or performs new analysis
func (arl *AIAdaptiveRateLimiter) getThreatInfo(ctx context.Context, request *AdaptiveRateLimitRequest) (*CachedThreatInfo, bool, error) {
	// If threat analysis is already provided, use it
	if request.ThreatAnalysis != nil {
		return &CachedThreatInfo{
			ThreatAnalysis:  request.ThreatAnalysis,
			ReputationScore: request.ReputationScore,
			CachedAt:        time.Now(),
		}, false, nil
	}
	
	// Generate cache key
	cacheKey := arl.generateCacheKey(request.RateLimitRequest)
	
	// Check cache first
	arl.mu.RLock()
	if cachedInfo, exists := arl.threatCache[cacheKey]; exists && time.Now().Before(cachedInfo.ExpiresAt) {
		arl.mu.RUnlock()
		return cachedInfo, true, nil
	}
	arl.mu.RUnlock()
	
	// Perform new threat analysis
	analysisRequest := arl.convertToThreatAnalysisRequest(request.RateLimitRequest)
	threatAnalysis, err := arl.threatDetector.AnalyzeRequest(ctx, analysisRequest)
	if err != nil {
		return nil, false, fmt.Errorf("threat analysis failed: %w", err)
	}
	
	// Calculate reputation score
	reputationScore := arl.calculateReputationScore(request.RateLimitRequest, threatAnalysis)
	
	// Create cached threat info
	threatInfo := &CachedThreatInfo{
		ThreatAnalysis:  threatAnalysis,
		ReputationScore: reputationScore,
		CachedAt:        time.Now(),
		ExpiresAt:       time.Now().Add(arl.config.ThreatCacheTimeout),
	}
	
	// Update cache
	arl.mu.Lock()
	arl.threatCache[cacheKey] = threatInfo
	
	// Clean up expired entries periodically
	if len(arl.threatCache) > 1000 {
		arl.cleanupExpiredCache()
	}
	arl.mu.Unlock()
	
	return threatInfo, false, nil
}

// calculateAdaptiveMultiplier calculates the rate limit multiplier based on threat analysis
func (arl *AIAdaptiveRateLimiter) calculateAdaptiveMultiplier(threatInfo *CachedThreatInfo) (float64, string) {
	multiplier := 1.0
	reasons := []string{}
	
	analysis := threatInfo.ThreatAnalysis
	
	// Base multiplier from threat level
	if analysis.IsThreat && arl.config.ThreatBasedAdjustment {
		if levelMultiplier, exists := arl.config.ThreatMultipliers[analysis.ThreatLevel]; exists {
			multiplier *= levelMultiplier
			reasons = append(reasons, fmt.Sprintf("threat_level_%s", analysis.ThreatLevel))
			
			arl.mu.Lock()
			arl.stats.ThreatBasedAdjustments++
			arl.stats.AdjustmentsByThreatLevel[analysis.ThreatLevel]++
			arl.mu.Unlock()
		}
		
		// Additional multiplier from threat type
		if typeMultiplier, exists := arl.config.ThreatTypeMultipliers[analysis.ThreatType]; exists {
			multiplier *= typeMultiplier
			reasons = append(reasons, fmt.Sprintf("threat_type_%s", analysis.ThreatType))
			
			arl.mu.Lock()
			arl.stats.AdjustmentsByThreatType[analysis.ThreatType]++
			arl.mu.Unlock()
		}
	}
	
	// Reputation-based adjustment
	if arl.config.BehavioralAdjustment {
		reputationMultiplier := arl.calculateReputationMultiplier(threatInfo.ReputationScore)
		if reputationMultiplier != 1.0 {
			multiplier *= reputationMultiplier
			reasons = append(reasons, fmt.Sprintf("reputation_%.2f", threatInfo.ReputationScore))
			
			arl.mu.Lock()
			arl.stats.BehavioralAdjustments++
			arl.mu.Unlock()
		}
	}
	
	// Progressive penalty for repeat offenders
	if arl.config.EnableProgressivePenalty && threatInfo.ViolationCount > 0 {
		penaltyMultiplier := math.Pow(arl.config.ProgressivePenaltyFactor, float64(threatInfo.ViolationCount))
		multiplier *= penaltyMultiplier
		reasons = append(reasons, fmt.Sprintf("progressive_penalty_%d", threatInfo.ViolationCount))
	}
	
	// Emergency mode
	if arl.config.EmergencyMode {
		multiplier *= arl.config.EmergencyMultiplier
		reasons = append(reasons, "emergency_mode")
	}
	
	// Apply bounds
	if multiplier < arl.config.MinRateLimitMultiplier {
		multiplier = arl.config.MinRateLimitMultiplier
		reasons = append(reasons, "min_bound")
	}
	if multiplier > arl.config.MaxRateLimitMultiplier {
		multiplier = arl.config.MaxRateLimitMultiplier
		reasons = append(reasons, "max_bound")
	}
	
	reasonStr := "standard"
	if len(reasons) > 0 {
		reasonStr = fmt.Sprintf("%v", reasons)
	}
	
	return multiplier, reasonStr
}

// applyAdaptiveMultiplier applies the calculated multiplier to rate limit parameters
func (arl *AIAdaptiveRateLimiter) applyAdaptiveMultiplier(request *ratelimit.RateLimitRequest, multiplier float64) *ratelimit.RateLimitRequest {
	if multiplier == 1.0 {
		return request
	}
	
	// Create a copy of the request
	adaptedRequest := *request
	
	// Adjust request size for bandwidth-based limiting
	if multiplier > 1.0 {
		// For threats, we want to consume more tokens (stricter limiting)
		adaptedRequest.RequestSize = int64(float64(request.RequestSize) * multiplier)
	} else {
		// For trusted users, we want to consume fewer tokens (more lenient)
		adaptedRequest.RequestSize = int64(float64(request.RequestSize) * multiplier)
		if adaptedRequest.RequestSize < 1 {
			adaptedRequest.RequestSize = 1
		}
	}
	
	// Add metadata about the adaptation
	if adaptedRequest.Metadata == nil {
		adaptedRequest.Metadata = make(map[string]interface{})
	}
	adaptedRequest.Metadata["ai_multiplier"] = multiplier
	adaptedRequest.Metadata["ai_adapted"] = true
	
	return &adaptedRequest
}

// Helper methods

func (arl *AIAdaptiveRateLimiter) isWhitelisted(request *AdaptiveRateLimitRequest) bool {
	// Check user whitelist
	for _, whitelistedUser := range arl.config.WhitelistedUsers {
		if request.UserID == whitelistedUser {
			return true
		}
	}
	
	// Check IP whitelist
	for _, whitelistedIP := range arl.config.WhitelistedIPs {
		if request.IP == whitelistedIP {
			return true
		}
	}
	
	return false
}

func (arl *AIAdaptiveRateLimiter) generateCacheKey(request *ratelimit.RateLimitRequest) string {
	// Generate a cache key based on user, IP, and time window
	timeWindow := time.Now().Truncate(arl.config.ThreatCacheTimeout / 2)
	return fmt.Sprintf("%s:%s:%d", request.UserID, request.IP, timeWindow.Unix())
}

func (arl *AIAdaptiveRateLimiter) convertToThreatAnalysisRequest(request *ratelimit.RateLimitRequest) *ThreatAnalysisRequest {
	return &ThreatAnalysisRequest{
		RequestID: fmt.Sprintf("adaptive-%d", time.Now().UnixNano()),
		Timestamp: request.Timestamp,
		ClientIP:  request.IP,
		UserAgent: request.UserAgent,
		Method:    request.Method,
		URL:       request.Endpoint,
		Headers:   request.Headers,
		UserID:    request.UserID,
		Metadata: map[string]interface{}{
			"org_id":       request.OrgID,
			"request_size": request.RequestSize,
		},
	}
}

func (arl *AIAdaptiveRateLimiter) calculateReputationScore(request *ratelimit.RateLimitRequest, analysis *ThreatAnalysisResult) float64 {
	// Base reputation score
	score := 0.5 // Neutral
	
	// Adjust based on threat analysis
	if analysis.IsThreat {
		score -= analysis.Confidence * 0.5
	} else {
		score += (1.0 - analysis.Confidence) * 0.3
	}
	
	// Ensure score is within bounds
	if score < 0.0 {
		score = 0.0
	}
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (arl *AIAdaptiveRateLimiter) calculateReputationMultiplier(reputationScore float64) float64 {
	// Convert reputation score to multiplier
	// High reputation (close to 1.0) = lower multiplier (more lenient)
	// Low reputation (close to 0.0) = higher multiplier (stricter)
	
	if reputationScore >= 0.8 {
		return 0.5 // Very lenient for high reputation
	} else if reputationScore >= 0.6 {
		return 0.8 // Somewhat lenient
	} else if reputationScore >= 0.4 {
		return 1.0 // Standard
	} else if reputationScore >= 0.2 {
		return 1.5 // Stricter
	} else {
		return 2.0 // Very strict for low reputation
	}
}

func (arl *AIAdaptiveRateLimiter) updateStats(analysis *ThreatAnalysisResult, multiplier float64, cacheHit bool) {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	// Update average multiplier (exponential moving average)
	alpha := 0.1
	if arl.stats.RequestsProcessed == 1 {
		arl.stats.AverageMultiplier = multiplier
	} else {
		arl.stats.AverageMultiplier = arl.stats.AverageMultiplier*(1-alpha) + multiplier*alpha
	}
	
	// Update cache hit rate
	if cacheHit {
		arl.stats.CacheHitRate = (arl.stats.CacheHitRate*float64(arl.stats.RequestsProcessed-1) + 1.0) / float64(arl.stats.RequestsProcessed)
	} else {
		arl.stats.CacheHitRate = (arl.stats.CacheHitRate * float64(arl.stats.RequestsProcessed-1)) / float64(arl.stats.RequestsProcessed)
	}
	
	arl.stats.CacheSize = len(arl.threatCache)
	arl.stats.LastUpdated = time.Now()
}

func (arl *AIAdaptiveRateLimiter) updateThreatCacheOnViolation(request *AdaptiveRateLimitRequest, threatInfo *CachedThreatInfo) {
	cacheKey := arl.generateCacheKey(request.RateLimitRequest)
	
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	if cachedInfo, exists := arl.threatCache[cacheKey]; exists {
		cachedInfo.ViolationCount++
		cachedInfo.LastViolation = time.Now()
		// Decrease reputation score on violation
		cachedInfo.ReputationScore *= 0.9
		if cachedInfo.ReputationScore < 0.0 {
			cachedInfo.ReputationScore = 0.0
		}
	}
}

func (arl *AIAdaptiveRateLimiter) cleanupExpiredCache() {
	now := time.Now()
	for key, info := range arl.threatCache {
		if now.After(info.ExpiresAt) {
			delete(arl.threatCache, key)
		}
	}
}

// ActivateEmergencyMode activates emergency mode for enhanced protection
func (arl *AIAdaptiveRateLimiter) ActivateEmergencyMode(reason string) {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	if !arl.config.EmergencyMode {
		arl.config.EmergencyMode = true
		arl.stats.EmergencyModeActivations++
		arl.stats.LastEmergencyMode = time.Now()
		
		arl.logger.Warnf("Emergency mode activated: %s", reason)
	}
}

// DeactivateEmergencyMode deactivates emergency mode
func (arl *AIAdaptiveRateLimiter) DeactivateEmergencyMode() {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	if arl.config.EmergencyMode {
		arl.config.EmergencyMode = false
		arl.logger.Info("Emergency mode deactivated")
	}
}

// Configuration and statistics methods

func (arl *AIAdaptiveRateLimiter) SetConfig(config *AdaptiveRateLimitConfig) {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	arl.config = config
	arl.logger.Info("Updated AI adaptive rate limiter configuration")
}

func (arl *AIAdaptiveRateLimiter) GetConfig() *AdaptiveRateLimitConfig {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	
	configCopy := *arl.config
	return &configCopy
}

func (arl *AIAdaptiveRateLimiter) GetStats() *AdaptiveRateLimitStats {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	
	statsCopy := *arl.stats
	
	// Deep copy maps
	statsCopy.AdjustmentsByThreatLevel = make(map[ThreatLevel]int64)
	for k, v := range arl.stats.AdjustmentsByThreatLevel {
		statsCopy.AdjustmentsByThreatLevel[k] = v
	}
	
	statsCopy.AdjustmentsByThreatType = make(map[ThreatType]int64)
	for k, v := range arl.stats.AdjustmentsByThreatType {
		statsCopy.AdjustmentsByThreatType[k] = v
	}
	
	return &statsCopy
}

func (arl *AIAdaptiveRateLimiter) ResetStats() {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	arl.stats = getDefaultAdaptiveRateLimitStats()
	arl.logger.Info("Reset AI adaptive rate limiter statistics")
}

// Default configurations

func getDefaultAdaptiveRateLimitConfig() *AdaptiveRateLimitConfig {
	return &AdaptiveRateLimitConfig{
		Enabled:               true,
		ThreatBasedAdjustment: true,
		BehavioralAdjustment:  true,
		ThreatMultipliers: map[ThreatLevel]float64{
			ThreatLevelCritical: 5.0,
			ThreatLevelHigh:     3.0,
			ThreatLevelMedium:   2.0,
			ThreatLevelLow:      1.5,
		},
		ThreatTypeMultipliers: map[ThreatType]float64{
			ThreatTypeMalware:    4.0,
			ThreatTypePhishing:   3.0,
			ThreatTypeBotnet:     3.5,
			ThreatTypeDDoS:       5.0,
			ThreatTypeSuspicious: 2.0,
		},
		MinRateLimitMultiplier:   0.1,
		MaxRateLimitMultiplier:   10.0,
		ThreatCacheTimeout:       5 * time.Minute,
		AdaptationSensitivity:    0.8,
		GracePeriod:              1 * time.Minute,
		EmergencyMode:            false,
		EmergencyThreshold:       0.9,
		EmergencyMultiplier:      2.0,
		WhitelistedUsers:         []string{},
		WhitelistedIPs:           []string{"127.0.0.1", "::1"},
		EnableProgressivePenalty: true,
		ProgressivePenaltyFactor: 1.5,
		ReputationDecayRate:      0.95,
	}
}

func getDefaultAdaptiveRateLimitStats() *AdaptiveRateLimitStats {
	return &AdaptiveRateLimitStats{
		AdjustmentsByThreatLevel: make(map[ThreatLevel]int64),
		AdjustmentsByThreatType:  make(map[ThreatType]int64),
		AverageMultiplier:        1.0,
		LastUpdated:              time.Now(),
	}
}