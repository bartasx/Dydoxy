package ai

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultBehavioralAnalyzer implements the BehavioralAnalyzer interface
type DefaultBehavioralAnalyzer struct {
	storage         AIStorage
	featureExtractor FeatureExtractor
	profiles        map[string]*BehaviorProfile
	config          *BehavioralConfig
	logger          *logrus.Logger
	mu              sync.RWMutex
}

// BehavioralConfig holds configuration for behavioral analysis
type BehavioralConfig struct {
	ProfileTTL           time.Duration `json:"profile_ttl"`
	MinRequestsForProfile int          `json:"min_requests_for_profile"`
	AnomalyThreshold     float64      `json:"anomaly_threshold"`
	UpdateInterval       time.Duration `json:"update_interval"`
	MaxProfileSize       int          `json:"max_profile_size"`
	EnableLearning       bool         `json:"enable_learning"`
	SensitivityLevel     float64      `json:"sensitivity_level"`
}

// BehavioralMetrics holds metrics for behavioral analysis
type BehavioralMetrics struct {
	RequestFrequency    float64            `json:"request_frequency"`
	AverageSessionTime  float64            `json:"average_session_time"`
	TimePatternScore    float64            `json:"time_pattern_score"`
	PathDiversityScore  float64            `json:"path_diversity_score"`
	UserAgentConsistency float64           `json:"user_agent_consistency"`
	GeoConsistency      float64            `json:"geo_consistency"`
	RequestSizeVariance float64            `json:"request_size_variance"`
	ErrorRate           float64            `json:"error_rate"`
	CustomMetrics       map[string]float64 `json:"custom_metrics"`
}

// NewDefaultBehavioralAnalyzer creates a new behavioral analyzer
func NewDefaultBehavioralAnalyzer(storage AIStorage, featureExtractor FeatureExtractor, logger *logrus.Logger) *DefaultBehavioralAnalyzer {
	return &DefaultBehavioralAnalyzer{
		storage:          storage,
		featureExtractor: featureExtractor,
		profiles:         make(map[string]*BehaviorProfile),
		config:           getDefaultBehavioralConfig(),
		logger:           logger,
	}
}

// AnalyzeBehavior analyzes behavior for anomalies
func (ba *DefaultBehavioralAnalyzer) AnalyzeBehavior(ctx context.Context, subject string, request *RequestContext) (*BehaviorAnalysis, error) {
	ba.mu.RLock()
	profile, exists := ba.profiles[subject]
	ba.mu.RUnlock()
	
	if !exists {
		// Try to load from storage
		var err error
		profile, err = ba.storage.LoadBehaviorProfile(ctx, subject)
		if err != nil {
			// Create new profile
			profile = ba.createNewProfile(subject, request)
		}
		
		ba.mu.Lock()
		ba.profiles[subject] = profile
		ba.mu.Unlock()
	}
	
	// Calculate behavioral metrics
	metrics := ba.calculateBehavioralMetrics(profile, request)
	
	// Detect anomalies
	anomalyScore, anomalyReasons := ba.detectAnomalies(profile, request, metrics)
	
	isAnomalous := anomalyScore >= ba.config.AnomalyThreshold
	
	analysis := &BehaviorAnalysis{
		Subject:        subject,
		IsAnomalous:    isAnomalous,
		AnomalyScore:   anomalyScore,
		AnomalyReasons: anomalyReasons,
		Profile:        profile,
		Timestamp:      time.Now(),
	}
	
	ba.logger.WithFields(logrus.Fields{
		"subject":        subject,
		"is_anomalous":   isAnomalous,
		"anomaly_score":  anomalyScore,
		"anomaly_reasons": len(anomalyReasons),
	}).Debug("Behavioral analysis completed")
	
	return analysis, nil
}

// UpdateProfile updates behavioral profile
func (ba *DefaultBehavioralAnalyzer) UpdateProfile(ctx context.Context, subject string, request *RequestContext) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	
	profile, exists := ba.profiles[subject]
	if !exists {
		// Try to load from storage
		var err error
		profile, err = ba.storage.LoadBehaviorProfile(ctx, subject)
		if err != nil {
			// Create new profile
			profile = ba.createNewProfile(subject, request)
		}
		ba.profiles[subject] = profile
	}
	
	// Update profile with new request data
	ba.updateProfileData(profile, request)
	
	// Save to storage periodically
	if time.Since(profile.UpdatedAt) > ba.config.UpdateInterval {
		if err := ba.storage.SaveBehaviorProfile(ctx, subject, profile); err != nil {
			ba.logger.Warnf("Failed to save behavior profile for %s: %v", subject, err)
		}
	}
	
	return nil
}

// GetProfile retrieves behavioral profile
func (ba *DefaultBehavioralAnalyzer) GetProfile(ctx context.Context, subject string) (*BehaviorProfile, error) {
	ba.mu.RLock()
	profile, exists := ba.profiles[subject]
	ba.mu.RUnlock()
	
	if exists {
		// Return a copy
		profileCopy := *profile
		return &profileCopy, nil
	}
	
	// Load from storage
	return ba.storage.LoadBehaviorProfile(ctx, subject)
}

// DetectAnomalies detects behavioral anomalies
func (ba *DefaultBehavioralAnalyzer) DetectAnomalies(ctx context.Context, subject string, request *RequestContext) (bool, float64, error) {
	analysis, err := ba.AnalyzeBehavior(ctx, subject, request)
	if err != nil {
		return false, 0, err
	}
	
	return analysis.IsAnomalous, analysis.AnomalyScore, nil
}

// TrainModel trains the behavioral analysis model
func (ba *DefaultBehavioralAnalyzer) TrainModel(ctx context.Context, data []*RequestContext) error {
	if !ba.config.EnableLearning {
		return fmt.Errorf("learning is disabled")
	}
	
	ba.logger.Infof("Training behavioral model with %d requests", len(data))
	
	// Group requests by subject
	subjectRequests := make(map[string][]*RequestContext)
	for _, request := range data {
		subject := ba.getSubjectFromRequest(request)
		subjectRequests[subject] = append(subjectRequests[subject], request)
	}
	
	// Update profiles for each subject
	for subject, requests := range subjectRequests {
		if len(requests) < ba.config.MinRequestsForProfile {
			continue
		}
		
		for _, request := range requests {
			if err := ba.UpdateProfile(ctx, subject, request); err != nil {
				ba.logger.Warnf("Failed to update profile for %s: %v", subject, err)
			}
		}
	}
	
	// Recalibrate anomaly thresholds based on training data
	if err := ba.recalibrateThresholds(ctx, subjectRequests); err != nil {
		ba.logger.Warnf("Failed to recalibrate thresholds: %v", err)
	}
	
	ba.logger.Info("Behavioral model training completed")
	return nil
}

// createNewProfile creates a new behavioral profile
func (ba *DefaultBehavioralAnalyzer) createNewProfile(subject string, request *RequestContext) *BehaviorProfile {
	now := time.Now()
	
	profile := &BehaviorProfile{
		Subject:          subject,
		FirstSeen:        now,
		LastSeen:         now,
		RequestCount:     1,
		AverageFrequency: 0,
		CommonUserAgents: []string{request.UserAgent},
		CommonPaths:      []string{request.Path},
		TimePatterns:     make(map[int]int64),
		GeoLocations:     []string{request.Country},
		TrustScore:       50.0, // Neutral starting score
		ViolationCount:   0,
		Metadata:         make(map[string]interface{}),
		UpdatedAt:        now,
	}
	
	// Initialize time pattern
	hour := request.Timestamp.Hour()
	profile.TimePatterns[hour] = 1
	
	return profile
}

// updateProfileData updates profile with new request data
func (ba *DefaultBehavioralAnalyzer) updateProfileData(profile *BehaviorProfile, request *RequestContext) {
	now := time.Now()
	
	// Update basic counters
	profile.RequestCount++
	profile.LastSeen = now
	
	// Update frequency (requests per hour)
	timeDiff := now.Sub(profile.FirstSeen).Hours()
	if timeDiff > 0 {
		profile.AverageFrequency = float64(profile.RequestCount) / timeDiff
	}
	
	// Update time patterns
	hour := request.Timestamp.Hour()
	profile.TimePatterns[hour]++
	
	// Update common user agents (keep top 5)
	ba.updateTopList(&profile.CommonUserAgents, request.UserAgent, 5)
	
	// Update common paths (keep top 10)
	ba.updateTopList(&profile.CommonPaths, request.Path, 10)
	
	// Update geo locations (keep top 3)
	if request.Country != "" {
		ba.updateTopList(&profile.GeoLocations, request.Country, 3)
	}
	
	// Update trust score based on behavior
	ba.updateTrustScore(profile, request)
	
	profile.UpdatedAt = now
}

// updateTopList updates a top-N list with a new item
func (ba *DefaultBehavioralAnalyzer) updateTopList(list *[]string, item string, maxSize int) {
	if item == "" {
		return
	}
	
	// Check if item already exists
	for i, existing := range *list {
		if existing == item {
			// Move to front
			if i > 0 {
				*list = append([]string{item}, append((*list)[:i], (*list)[i+1:]...)...)
			}
			return
		}
	}
	
	// Add new item to front
	*list = append([]string{item}, *list...)
	
	// Trim to max size
	if len(*list) > maxSize {
		*list = (*list)[:maxSize]
	}
}

// updateTrustScore updates the trust score based on current behavior
func (ba *DefaultBehavioralAnalyzer) updateTrustScore(profile *BehaviorProfile, request *RequestContext) {
	// Increase trust for consistent behavior
	if ba.isConsistentBehavior(profile, request) {
		profile.TrustScore = math.Min(100, profile.TrustScore+0.1)
	}
	
	// Decrease trust for suspicious patterns
	if ba.isSuspiciousBehavior(profile, request) {
		profile.TrustScore = math.Max(0, profile.TrustScore-1.0)
	}
	
	// Age-based trust increase (older accounts are more trusted)
	accountAge := time.Since(profile.FirstSeen).Hours() / 24 // days
	if accountAge > 30 { // After 30 days
		profile.TrustScore = math.Min(100, profile.TrustScore+0.01)
	}
}

// calculateBehavioralMetrics calculates behavioral metrics for analysis
func (ba *DefaultBehavioralAnalyzer) calculateBehavioralMetrics(profile *BehaviorProfile, request *RequestContext) *BehavioralMetrics {
	metrics := &BehavioralMetrics{
		CustomMetrics: make(map[string]float64),
	}
	
	// Request frequency metric
	metrics.RequestFrequency = profile.AverageFrequency
	
	// Time pattern consistency
	metrics.TimePatternScore = ba.calculateTimePatternScore(profile, request)
	
	// Path diversity
	metrics.PathDiversityScore = ba.calculatePathDiversity(profile)
	
	// User agent consistency
	metrics.UserAgentConsistency = ba.calculateUserAgentConsistency(profile, request)
	
	// Geographic consistency
	metrics.GeoConsistency = ba.calculateGeoConsistency(profile, request)
	
	// Request size variance (placeholder - would need historical data)
	metrics.RequestSizeVariance = 0.5
	
	// Error rate (placeholder - would need error tracking)
	metrics.ErrorRate = 0.1
	
	return metrics
}

// detectAnomalies detects anomalies in behavior
func (ba *DefaultBehavioralAnalyzer) detectAnomalies(profile *BehaviorProfile, request *RequestContext, metrics *BehavioralMetrics) (float64, []string) {
	var anomalyScore float64
	var reasons []string
	
	// Check request frequency anomaly
	if metrics.RequestFrequency > profile.AverageFrequency*3 {
		anomalyScore += 0.3
		reasons = append(reasons, "Unusual request frequency")
	}
	
	// Check time pattern anomaly
	if metrics.TimePatternScore < 0.3 {
		anomalyScore += 0.2
		reasons = append(reasons, "Unusual time pattern")
	}
	
	// Check user agent consistency
	if metrics.UserAgentConsistency < 0.5 {
		anomalyScore += 0.2
		reasons = append(reasons, "Inconsistent user agent")
	}
	
	// Check geographic consistency
	if metrics.GeoConsistency < 0.3 {
		anomalyScore += 0.25
		reasons = append(reasons, "Unusual geographic location")
	}
	
	// Check trust score
	if profile.TrustScore < 30 {
		anomalyScore += 0.15
		reasons = append(reasons, "Low trust score")
	}
	
	// Check violation history
	if profile.ViolationCount > 5 {
		anomalyScore += 0.1
		reasons = append(reasons, "High violation count")
	}
	
	// Apply sensitivity adjustment
	anomalyScore *= ba.config.SensitivityLevel
	
	return math.Min(1.0, anomalyScore), reasons
}

// calculateTimePatternScore calculates how consistent the request time is with historical patterns
func (ba *DefaultBehavioralAnalyzer) calculateTimePatternScore(profile *BehaviorProfile, request *RequestContext) float64 {
	if len(profile.TimePatterns) == 0 {
		return 0.5 // Neutral score for new profiles
	}
	
	currentHour := request.Timestamp.Hour()
	currentCount := profile.TimePatterns[currentHour]
	
	// Calculate total requests
	var totalRequests int64
	for _, count := range profile.TimePatterns {
		totalRequests += count
	}
	
	if totalRequests == 0 {
		return 0.5
	}
	
	// Calculate probability of this hour
	probability := float64(currentCount) / float64(totalRequests)
	
	// Convert to score (higher probability = higher score)
	return probability
}

// calculatePathDiversity calculates path diversity score
func (ba *DefaultBehavioralAnalyzer) calculatePathDiversity(profile *BehaviorProfile) float64 {
	uniquePaths := len(profile.CommonPaths)
	if uniquePaths == 0 {
		return 0
	}
	
	// Normalize based on request count
	diversity := float64(uniquePaths) / math.Log(float64(profile.RequestCount)+1)
	return math.Min(1.0, diversity)
}

// calculateUserAgentConsistency calculates user agent consistency
func (ba *DefaultBehavioralAnalyzer) calculateUserAgentConsistency(profile *BehaviorProfile, request *RequestContext) float64 {
	if len(profile.CommonUserAgents) == 0 {
		return 0.5
	}
	
	// Check if current user agent is in common list
	for _, ua := range profile.CommonUserAgents {
		if ua == request.UserAgent {
			return 1.0
		}
	}
	
	// Check similarity to common user agents
	maxSimilarity := 0.0
	for _, ua := range profile.CommonUserAgents {
		similarity := ba.calculateStringSimilarity(ua, request.UserAgent)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}
	
	return maxSimilarity
}

// calculateGeoConsistency calculates geographic consistency
func (ba *DefaultBehavioralAnalyzer) calculateGeoConsistency(profile *BehaviorProfile, request *RequestContext) float64 {
	if request.Country == "" || len(profile.GeoLocations) == 0 {
		return 0.5
	}
	
	// Check if current country is in common list
	for _, country := range profile.GeoLocations {
		if country == request.Country {
			return 1.0
		}
	}
	
	return 0.0 // New country
}

// calculateStringSimilarity calculates similarity between two strings
func (ba *DefaultBehavioralAnalyzer) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	
	// Simple similarity based on common substrings
	shorter, longer := s1, s2
	if len(s1) > len(s2) {
		shorter, longer = s2, s1
	}
	
	if len(shorter) == 0 {
		return 0.0
	}
	
	matches := 0
	for i := 0; i < len(shorter); i++ {
		if i < len(longer) && shorter[i] == longer[i] {
			matches++
		}
	}
	
	return float64(matches) / float64(len(longer))
}

// isConsistentBehavior checks if behavior is consistent with profile
func (ba *DefaultBehavioralAnalyzer) isConsistentBehavior(profile *BehaviorProfile, request *RequestContext) bool {
	// Check if user agent is consistent
	for _, ua := range profile.CommonUserAgents {
		if ua == request.UserAgent {
			return true
		}
	}
	
	// Check if path is common
	for _, path := range profile.CommonPaths {
		if path == request.Path {
			return true
		}
	}
	
	return false
}

// isSuspiciousBehavior checks if behavior is suspicious
func (ba *DefaultBehavioralAnalyzer) isSuspiciousBehavior(profile *BehaviorProfile, request *RequestContext) bool {
	// Check for rapid requests (potential bot behavior)
	if profile.AverageFrequency > 100 { // More than 100 requests per hour
		return true
	}
	
	// Check for unusual time patterns (e.g., only night requests)
	hour := request.Timestamp.Hour()
	if hour >= 2 && hour <= 5 && profile.RequestCount > 10 {
		// Check if most requests are during night hours
		nightRequests := int64(0)
		for h := 2; h <= 5; h++ {
			nightRequests += profile.TimePatterns[h]
		}
		if float64(nightRequests)/float64(profile.RequestCount) > 0.8 {
			return true
		}
	}
	
	return false
}

// getSubjectFromRequest extracts subject identifier from request
func (ba *DefaultBehavioralAnalyzer) getSubjectFromRequest(request *RequestContext) string {
	if request.UserID != "" {
		return fmt.Sprintf("user:%s", request.UserID)
	}
	return fmt.Sprintf("ip:%s", request.SourceIP.String())
}

// recalibrateThresholds recalibrates anomaly thresholds based on training data
func (ba *DefaultBehavioralAnalyzer) recalibrateThresholds(ctx context.Context, subjectRequests map[string][]*RequestContext) error {
	var allScores []float64
	
	// Calculate anomaly scores for all subjects
	for subject, requests := range subjectRequests {
		profile, exists := ba.profiles[subject]
		if !exists {
			continue
		}
		
		for _, request := range requests {
			metrics := ba.calculateBehavioralMetrics(profile, request)
			score, _ := ba.detectAnomalies(profile, request, metrics)
			allScores = append(allScores, score)
		}
	}
	
	if len(allScores) == 0 {
		return fmt.Errorf("no scores to calibrate")
	}
	
	// Sort scores
	sort.Float64s(allScores)
	
	// Set threshold at 95th percentile
	thresholdIndex := int(float64(len(allScores)) * 0.95)
	if thresholdIndex >= len(allScores) {
		thresholdIndex = len(allScores) - 1
	}
	
	newThreshold := allScores[thresholdIndex]
	ba.config.AnomalyThreshold = newThreshold
	
	ba.logger.Infof("Recalibrated anomaly threshold to %.3f", newThreshold)
	return nil
}

// getDefaultBehavioralConfig returns default behavioral analysis configuration
func getDefaultBehavioralConfig() *BehavioralConfig {
	return &BehavioralConfig{
		ProfileTTL:            30 * 24 * time.Hour, // 30 days
		MinRequestsForProfile: 10,
		AnomalyThreshold:      0.7,
		UpdateInterval:        5 * time.Minute,
		MaxProfileSize:        1000,
		EnableLearning:        true,
		SensitivityLevel:      1.0,
	}
}

// SetConfig updates the behavioral analysis configuration
func (ba *DefaultBehavioralAnalyzer) SetConfig(config *BehavioralConfig) {
	ba.config = config
	ba.logger.Info("Updated behavioral analysis configuration")
}

// GetConfig returns the current configuration
func (ba *DefaultBehavioralAnalyzer) GetConfig() *BehavioralConfig {
	return ba.config
}

// GetStats returns behavioral analysis statistics
func (ba *DefaultBehavioralAnalyzer) GetStats() map[string]interface{} {
	ba.mu.RLock()
	defer ba.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_profiles":     len(ba.profiles),
		"anomaly_threshold":  ba.config.AnomalyThreshold,
		"learning_enabled":   ba.config.EnableLearning,
		"sensitivity_level":  ba.config.SensitivityLevel,
		"last_updated":       time.Now(),
	}
	
	// Calculate profile statistics
	var totalRequests int64
	var avgTrustScore float64
	
	for _, profile := range ba.profiles {
		totalRequests += profile.RequestCount
		avgTrustScore += profile.TrustScore
	}
	
	if len(ba.profiles) > 0 {
		avgTrustScore /= float64(len(ba.profiles))
	}
	
	stats["total_requests"] = totalRequests
	stats["average_trust_score"] = avgTrustScore
	
	return stats
}