package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/dydoxy/proxy-engine-go/internal/security/filter"
	"github.com/sirupsen/logrus"
)

// AIEnhancedContentFilter wraps the existing content filter with AI capabilities
type AIEnhancedContentFilter struct {
	baseFilter      filter.ContentFilter
	aiDetector      ai.AIThreatDetector
	featureExtractor ai.FeatureExtractor
	config          *AIFilterConfig
	logger          *logrus.Logger
	stats           *AIFilterStats
}

// AIFilterConfig holds configuration for AI-enhanced filtering
type AIFilterConfig struct {
	AIEnabled           bool    `json:"ai_enabled"`
	ConfidenceThreshold float64 `json:"confidence_threshold"`
	FallbackOnError     bool    `json:"fallback_on_error"`
	MaxProcessingTime   time.Duration `json:"max_processing_time"`
	LogAIDecisions      bool    `json:"log_ai_decisions"`
	CombineResults      bool    `json:"combine_results"`
}

// AIFilterStats tracks AI filtering statistics
type AIFilterStats struct {
	TotalRequests       int64 `json:"total_requests"`
	AIAnalyzedRequests  int64 `json:"ai_analyzed_requests"`
	AIBlockedRequests   int64 `json:"ai_blocked_requests"`
	AIAllowedRequests   int64 `json:"ai_allowed_requests"`
	TraditionalBlocked  int64 `json:"traditional_blocked"`
	CombinedDecisions   int64 `json:"combined_decisions"`
	AIErrors            int64 `json:"ai_errors"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
}

// NewAIEnhancedContentFilter creates a new AI-enhanced content filter
func NewAIEnhancedContentFilter(baseFilter filter.ContentFilter, aiDetector ai.AIThreatDetector, featureExtractor ai.FeatureExtractor, logger *logrus.Logger) *AIEnhancedContentFilter {
	return &AIEnhancedContentFilter{
		baseFilter:       baseFilter,
		aiDetector:       aiDetector,
		featureExtractor: featureExtractor,
		config:           getDefaultAIFilterConfig(),
		logger:           logger,
		stats:            &AIFilterStats{},
	}
}

// Filter performs enhanced content filtering with AI analysis
func (f *AIEnhancedContentFilter) Filter(ctx context.Context, request *filter.ContentRequest) (*filter.FilterResult, error) {
	f.stats.TotalRequests++
	startTime := time.Now()
	
	// First run traditional content filtering
	baseResult, err := f.baseFilter.Filter(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("base filter error: %w", err)
	}
	
	// If AI is disabled, return base result
	if !f.config.AIEnabled {
		return baseResult, nil
	}
	
	// If blocked by traditional rules and not combining results, return immediately
	if !baseResult.Allowed && !f.config.CombineResults {
		f.stats.TraditionalBlocked++
		return baseResult, nil
	}
	
	// Run AI analysis
	aiResult, aiErr := f.runAIAnalysis(ctx, request)
	processingTime := time.Since(startTime)
	f.updateProcessingTime(processingTime)
	
	if aiErr != nil {
		f.stats.AIErrors++
		f.logger.Warnf("AI analysis failed: %v", aiErr)
		
		if f.config.FallbackOnError {
			return baseResult, nil
		}
		return nil, fmt.Errorf("AI analysis failed: %w", aiErr)
	}
	
	f.stats.AIAnalyzedRequests++
	
	// Combine results
	finalResult := f.combineResults(baseResult, aiResult, request)
	
	// Log AI decisions if enabled
	if f.config.LogAIDecisions {
		f.logAIDecision(request, baseResult, aiResult, finalResult)
	}
	
	// Update statistics
	if finalResult.Allowed {
		f.stats.AIAllowedRequests++
	} else {
		f.stats.AIBlockedRequests++
	}
	
	if f.isDifferentDecision(baseResult, finalResult) {
		f.stats.CombinedDecisions++
	}
	
	return finalResult, nil
}

// runAIAnalysis performs AI threat analysis on the request
func (f *AIEnhancedContentFilter) runAIAnalysis(ctx context.Context, request *filter.ContentRequest) (*ai.ThreatAnalysisResult, error) {
	// Create context with timeout
	aiCtx, cancel := context.WithTimeout(ctx, f.config.MaxProcessingTime)
	defer cancel()
	
	// Convert filter request to AI request
	aiRequest := f.convertToAIRequest(request)
	
	// Perform AI analysis
	result, err := f.aiDetector.AnalyzeRequest(aiCtx, aiRequest)
	if err != nil {
		return nil, fmt.Errorf("AI detector failed: %w", err)
	}
	
	return result, nil
}

// combineResults combines traditional and AI filtering results
func (f *AIEnhancedContentFilter) combineResults(baseResult *filter.FilterResult, aiResult *ai.ThreatAnalysisResult, request *filter.ContentRequest) *filter.FilterResult {
	// Start with base result
	result := &filter.FilterResult{
		Allowed:     baseResult.Allowed,
		Action:      baseResult.Action,
		MatchedRule: baseResult.MatchedRule,
		Reason:      baseResult.Reason,
		Timestamp:   time.Now(),
	}
	
	// Apply AI analysis
	if aiResult.IsThreat && aiResult.Confidence >= f.config.ConfidenceThreshold {
		// AI detected a threat with sufficient confidence
		result.Allowed = false
		result.Action = f.mapThreatToAction(aiResult.ThreatType, aiResult.ThreatLevel)
		
		// Combine reasons
		aiReason := fmt.Sprintf("AI detected %s (confidence: %.2f)", aiResult.ThreatType, aiResult.Confidence)
		if result.Reason != "" {
			result.Reason = fmt.Sprintf("%s; %s", result.Reason, aiReason)
		} else {
			result.Reason = aiReason
		}
		
		// Add AI metadata
		if result.MatchedRule == nil {
			// Create a virtual rule for AI detection
			result.MatchedRule = &filter.FilterRule{
				ID:          fmt.Sprintf("ai-%s", aiResult.ThreatType),
				Name:        fmt.Sprintf("AI %s Detection", aiResult.ThreatType),
				Type:        filter.RuleTypeRegex, // Generic type
				Action:      result.Action,
				Priority:    1000, // High priority for AI rules
				Enabled:     true,
				Description: fmt.Sprintf("AI-detected %s threat", aiResult.ThreatType),
			}
		}
	} else if !baseResult.Allowed && aiResult.Confidence < f.config.ConfidenceThreshold {
		// Traditional filter blocked but AI has low confidence - potentially allow
		if f.config.CombineResults && aiResult.Confidence < 0.3 {
			result.Allowed = true
			result.Action = filter.ActionAllow
			result.Reason = fmt.Sprintf("%s; AI low confidence override (%.2f)", result.Reason, aiResult.Confidence)
		}
	}
	
	return result
}

// convertToAIRequest converts filter request to AI request format
func (f *AIEnhancedContentFilter) convertToAIRequest(request *filter.ContentRequest) *ai.ThreatAnalysisRequest {
	return &ai.ThreatAnalysisRequest{
		RequestID:     fmt.Sprintf("filter-%d", time.Now().UnixNano()),
		URL:           request.URL,
		Domain:        request.Domain,
		Method:        request.Method,
		Headers:       request.Headers,
		ContentType:   request.ContentType,
		UserID:        request.UserID,
		OrgID:         request.OrgID,
		Body:          request.Body,
		Timestamp:     time.Now(),
	}
}

// mapThreatToAction maps AI threat types to filter actions
func (f *AIEnhancedContentFilter) mapThreatToAction(threatType ai.ThreatType, threatLevel ai.ThreatLevel) filter.FilterAction {
	// High-severity threats are blocked
	if threatLevel >= ai.ThreatLevelHigh {
		return filter.ActionBlock
	}
	
	// Map specific threat types
	switch threatType {
	case ai.ThreatTypeMalware, ai.ThreatTypePhishing:
		return filter.ActionBlock
	case ai.ThreatTypeBotnet, ai.ThreatTypeCommandControl:
		return filter.ActionBlock
	case ai.ThreatTypeDataExfiltration:
		return filter.ActionQuarantine
	case ai.ThreatTypeZeroDay:
		return filter.ActionQuarantine
	case ai.ThreatTypeInsiderThreat:
		return filter.ActionLog
	case ai.ThreatTypeSuspicious:
		if threatLevel >= ai.ThreatLevelMedium {
			return filter.ActionLog
		}
		return filter.ActionAllow
	default:
		return filter.ActionLog
	}
}

// isDifferentDecision checks if AI changed the traditional filtering decision
func (f *AIEnhancedContentFilter) isDifferentDecision(baseResult, finalResult *filter.FilterResult) bool {
	return baseResult.Allowed != finalResult.Allowed
}

// logAIDecision logs AI filtering decisions for analysis
func (f *AIEnhancedContentFilter) logAIDecision(request *filter.ContentRequest, baseResult *filter.FilterResult, aiResult *ai.ThreatAnalysisResult, finalResult *filter.FilterResult) {
	f.logger.WithFields(logrus.Fields{
		"url":              request.URL,
		"user_id":          request.UserID,
		"org_id":           request.OrgID,
		"base_allowed":     baseResult.Allowed,
		"base_reason":      baseResult.Reason,
		"ai_threat":        aiResult.IsThreat,
		"ai_type":          aiResult.ThreatType,
		"ai_level":         aiResult.ThreatLevel,
		"ai_confidence":    aiResult.Confidence,
		"final_allowed":    finalResult.Allowed,
		"final_action":     finalResult.Action,
		"decision_changed": f.isDifferentDecision(baseResult, finalResult),
	}).Info("AI filtering decision")
}

// updateProcessingTime updates average processing time statistics
func (f *AIEnhancedContentFilter) updateProcessingTime(duration time.Duration) {
	if f.stats.AIAnalyzedRequests == 1 {
		f.stats.AverageProcessingTime = duration
	} else {
		// Calculate running average
		total := f.stats.AverageProcessingTime * time.Duration(f.stats.AIAnalyzedRequests-1)
		f.stats.AverageProcessingTime = (total + duration) / time.Duration(f.stats.AIAnalyzedRequests)
	}
}

// Configuration methods

// SetConfig updates the AI filter configuration
func (f *AIEnhancedContentFilter) SetConfig(config *AIFilterConfig) {
	f.config = config
	f.logger.Info("Updated AI filter configuration")
}

// GetConfig returns the current AI filter configuration
func (f *AIEnhancedContentFilter) GetConfig() *AIFilterConfig {
	return f.config
}

// GetStats returns AI filtering statistics
func (f *AIEnhancedContentFilter) GetStats() *AIFilterStats {
	return f.stats
}

// ResetStats resets AI filtering statistics
func (f *AIEnhancedContentFilter) ResetStats() {
	f.stats = &AIFilterStats{}
	f.logger.Info("Reset AI filter statistics")
}

// Pass-through methods to base filter

// AddRule adds a rule to the base filter
func (f *AIEnhancedContentFilter) AddRule(ctx context.Context, rule *filter.FilterRule) error {
	return f.baseFilter.AddRule(ctx, rule)
}

// RemoveRule removes a rule from the base filter
func (f *AIEnhancedContentFilter) RemoveRule(ctx context.Context, ruleID string) error {
	return f.baseFilter.RemoveRule(ctx, ruleID)
}

// UpdateRule updates a rule in the base filter
func (f *AIEnhancedContentFilter) UpdateRule(ctx context.Context, rule *filter.FilterRule) error {
	return f.baseFilter.UpdateRule(ctx, rule)
}

// GetRules returns rules from the base filter
func (f *AIEnhancedContentFilter) GetRules(ctx context.Context) ([]*filter.FilterRule, error) {
	return f.baseFilter.GetRules(ctx)
}

// GetRulesByType returns rules by type from the base filter
func (f *AIEnhancedContentFilter) GetRulesByType(ctx context.Context, ruleType filter.RuleType) ([]*filter.FilterRule, error) {
	return f.baseFilter.GetRulesByType(ctx, ruleType)
}

// GetStats returns combined statistics from base filter and AI
func (f *AIEnhancedContentFilter) GetFilterStats(ctx context.Context) (*filter.FilterStats, error) {
	baseStats, err := f.baseFilter.GetStats(ctx)
	if err != nil {
		return nil, err
	}
	
	// Combine with AI stats
	combinedStats := &filter.FilterStats{
		TotalRequests:   f.stats.TotalRequests,
		BlockedRequests: baseStats.BlockedRequests + f.stats.AIBlockedRequests,
		AllowedRequests: baseStats.AllowedRequests + f.stats.AIAllowedRequests,
		LoggedRequests:  baseStats.LoggedRequests,
	}
	
	return combinedStats, nil
}

// ReloadRules reloads rules in the base filter
func (f *AIEnhancedContentFilter) ReloadRules(ctx context.Context) error {
	return f.baseFilter.ReloadRules(ctx)
}

// Helper functions

// getDefaultAIFilterConfig returns default AI filter configuration
func getDefaultAIFilterConfig() *AIFilterConfig {
	return &AIFilterConfig{
		AIEnabled:           true,
		ConfidenceThreshold: 0.7,
		FallbackOnError:     true,
		MaxProcessingTime:   50 * time.Millisecond,
		LogAIDecisions:      true,
		CombineResults:      true,
	}
}

// AIFilterMiddleware creates middleware for AI-enhanced filtering
func (f *AIEnhancedContentFilter) AIFilterMiddleware() func(ctx context.Context, request *filter.ContentRequest) (*filter.FilterResult, error) {
	return func(ctx context.Context, request *filter.ContentRequest) (*filter.FilterResult, error) {
		return f.Filter(ctx, request)
	}
}

// GetAIThreatIntelligence returns threat intelligence from AI detector
func (f *AIEnhancedContentFilter) GetAIThreatIntelligence(ctx context.Context, query *ai.ThreatQuery) (*ai.ThreatIntelligence, error) {
	return f.aiDetector.GetThreatIntelligence(ctx, query)
}

// UpdateAIPolicies updates AI threat detection policies
func (f *AIEnhancedContentFilter) UpdateAIPolicies(ctx context.Context, policies *ai.ThreatPolicies) error {
	return f.aiDetector.ConfigurePolicies(ctx, policies)
}

// GetAIStats returns AI threat detection statistics
func (f *AIEnhancedContentFilter) GetAIStats(ctx context.Context) (*ai.AIThreatStats, error) {
	return f.aiDetector.GetStats(ctx)
}

// GetAIHealth returns AI system health status
func (f *AIEnhancedContentFilter) GetAIHealth(ctx context.Context) (*ai.AIHealthStatus, error) {
	return f.aiDetector.GetHealth(ctx)
}