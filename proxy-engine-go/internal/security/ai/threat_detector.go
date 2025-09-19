package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultThreatDetector implements the AIThreatDetector interface
type DefaultThreatDetector struct {
	storage            AIStorage
	featureExtractor   FeatureExtractor
	behavioralAnalyzer BehavioralAnalyzer
	anomalyDetector    *AnomalyDetector
	contentModel       MLModel
	policies           *ThreatPolicies
	stats              *AIThreatStats
	logger             *logrus.Logger
	mu                 sync.RWMutex
}

// NewDefaultThreatDetector creates a new threat detector
func NewDefaultThreatDetector(storage AIStorage, featureExtractor FeatureExtractor, behavioralAnalyzer BehavioralAnalyzer, logger *logrus.Logger) *DefaultThreatDetector {
	detector := &DefaultThreatDetector{
		storage:            storage,
		featureExtractor:   featureExtractor,
		behavioralAnalyzer: behavioralAnalyzer,
		anomalyDetector:    NewAnomalyDetector(logger),
		policies:           getDefaultThreatPolicies(),
		stats:              getDefaultAIThreatStats(),
		logger:             logger,
	}
	
	// Load policies from storage
	if policies, err := storage.LoadThreatPolicies(context.Background()); err == nil {
		detector.policies = policies
	}
	
	// Load stats from storage
	if stats, err := storage.LoadAIStats(context.Background()); err == nil {
		detector.stats = stats
	}
	
	return detector
}

// AnalyzeRequest performs comprehensive threat analysis
func (td *DefaultThreatDetector) AnalyzeRequest(ctx context.Context, request *ThreatAnalysisRequest) (*ThreatAnalysisResult, error) {
	startTime := time.Now()
	
	td.mu.Lock()
	td.stats.TotalRequests++
	td.mu.Unlock()
	
	// Check if AI is globally enabled
	if !td.policies.GlobalEnabled {
		return &ThreatAnalysisResult{
			RequestID:         request.RequestID,
			IsThreat:          false,
			ThreatLevel:       ThreatLevelLow,
			Confidence:        0.0,
			RecommendedAction: ActionAllow,
			Reason:            "AI threat detection is disabled",
			ProcessingTime:    time.Since(startTime),
			Timestamp:         time.Now(),
		}, nil
	}
	
	result := &ThreatAnalysisResult{
		RequestID:      request.RequestID,
		MLPredictions:  make([]*MLPrediction, 0),
		ThreatPatterns: make([]*ThreatPattern, 0),
		Metadata:       make(map[string]interface{}),
		Timestamp:      time.Now(),
	}
	
	// Extract features
	features, err := td.featureExtractor.ExtractFeatures(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("feature extraction failed: %w", err)
	}
	
	// Content analysis using ML model
	if td.policies.MachineLearning && td.contentModel != nil {
		mlPrediction, err := td.analyzeWithMLModel(ctx, features)
		if err != nil {
			td.logger.Warnf("ML model analysis failed: %v", err)
		} else {
			result.MLPredictions = append(result.MLPredictions, mlPrediction)
		}
	}
	
	// Behavioral analysis
	if td.policies.BehavioralAnalysis {
		behaviorAnalysis, err := td.analyzeBehavior(ctx, request)
		if err != nil {
			td.logger.Warnf("Behavioral analysis failed: %v", err)
		} else {
			result.BehaviorAnalysis = behaviorAnalysis
		}
	}
	
	// Threat intelligence analysis
	if td.policies.ThreatIntelligence {
		threatPatterns, err := td.analyzeThreatIntelligence(ctx, request)
		if err != nil {
			td.logger.Warnf("Threat intelligence analysis failed: %v", err)
		} else {
			result.ThreatPatterns = threatPatterns
		}
	}
	
	// Combine all analysis results
	td.combineAnalysisResults(result)
	
	// Apply policies and determine final decision
	td.applyThreatPolicies(result)
	
	// Update statistics
	td.updateStatistics(result)
	
	// Save analysis result
	result.ProcessingTime = time.Since(startTime)
	if err := td.storage.SaveThreatAnalysis(ctx, result); err != nil {
		td.logger.Warnf("Failed to save threat analysis: %v", err)
	}
	
	td.logger.WithFields(logrus.Fields{
		"request_id":    result.RequestID,
		"is_threat":     result.IsThreat,
		"threat_type":   result.ThreatType,
		"threat_level":  result.ThreatLevel,
		"confidence":    result.Confidence,
		"processing_time": result.ProcessingTime,
	}).Debug("Threat analysis completed")
	
	return result, nil
}

// analyzeWithMLModel performs ML-based content analysis
func (td *DefaultThreatDetector) analyzeWithMLModel(ctx context.Context, features *FeatureVector) (*MLPrediction, error) {
	if td.contentModel == nil {
		return nil, fmt.Errorf("content model not available")
	}
	
	featureMap := features.ToMap()
	return td.contentModel.Predict(ctx, featureMap)
}

// analyzeBehavior performs behavioral analysis
func (td *DefaultThreatDetector) analyzeBehavior(ctx context.Context, request *ThreatAnalysisRequest) (*BehaviorAnalysis, error) {
	// Convert to RequestContext
	requestContext := &RequestContext{
		SourceIP:      request.SourceIP,
		UserAgent:     request.UserAgent,
		Method:        request.Method,
		Path:          extractPathFromURL(request.URL),
		Headers:       request.Headers,
		ContentLength: request.ContentLength,
		Timestamp:     request.Timestamp,
		UserID:        request.UserID,
		Country:       extractCountryFromContext(request.Context),
	}
	
	// Determine subject (user or IP)
	subject := td.getSubjectIdentifier(request)
	
	// Perform behavioral analysis
	return td.behavioralAnalyzer.AnalyzeBehavior(ctx, subject, requestContext)
}

// analyzeThreatIntelligence performs threat intelligence analysis
func (td *DefaultThreatDetector) analyzeThreatIntelligence(ctx context.Context, request *ThreatAnalysisRequest) ([]*ThreatPattern, error) {
	var patterns []*ThreatPattern
	
	// Check domain reputation
	if domain := extractDomainFromURL(request.URL); domain != "" {
		if pattern := td.checkDomainThreatIntelligence(domain); pattern != nil {
			patterns = append(patterns, pattern)
		}
	}
	
	// Check IP reputation
	if request.SourceIP != nil {
		if pattern := td.checkIPThreatIntelligence(request.SourceIP.String()); pattern != nil {
			patterns = append(patterns, pattern)
		}
	}
	
	// Check user agent patterns
	if request.UserAgent != "" {
		if pattern := td.checkUserAgentPatterns(request.UserAgent); pattern != nil {
			patterns = append(patterns, pattern)
		}
	}
	
	return patterns, nil
}

// combineAnalysisResults combines results from different analysis methods
func (td *DefaultThreatDetector) combineAnalysisResults(result *ThreatAnalysisResult) {
	var threatScores []float64
	var threatTypes []ThreatType
	var threatLevels []ThreatLevel
	var reasons []string
	
	// Process ML predictions
	for _, prediction := range result.MLPredictions {
		if prediction.IsThreat {
			threatScores = append(threatScores, prediction.Confidence)
			threatTypes = append(threatTypes, prediction.ThreatType)
			reasons = append(reasons, fmt.Sprintf("ML model detected %s", prediction.ThreatType))
		}
	}
	
	// Process behavioral analysis
	if result.BehaviorAnalysis != nil && result.BehaviorAnalysis.IsAnomalous {
		threatScores = append(threatScores, result.BehaviorAnalysis.AnomalyScore)
		threatTypes = append(threatTypes, ThreatTypeAnomalous)
		reasons = append(reasons, "Anomalous behavior detected")
		reasons = append(reasons, result.BehaviorAnalysis.AnomalyReasons...)
	}
	
	// Process threat intelligence
	for _, pattern := range result.ThreatPatterns {
		threatScores = append(threatScores, pattern.Confidence)
		threatTypes = append(threatTypes, pattern.Type)
		reasons = append(reasons, fmt.Sprintf("Threat pattern matched: %s", pattern.Name))
	}
	
	// Calculate combined threat score
	if len(threatScores) == 0 {
		result.IsThreat = false
		result.Confidence = 0.0
		result.ThreatLevel = ThreatLevelLow
		result.Reason = "No threats detected"
		return
	}
	
	// Use maximum threat score as overall confidence
	maxScore := 0.0
	maxIndex := 0
	for i, score := range threatScores {
		if score > maxScore {
			maxScore = score
			maxIndex = i
		}
	}
	
	result.Confidence = maxScore
	if maxIndex < len(threatTypes) {
		result.ThreatType = threatTypes[maxIndex]
	}
	
	// Determine threat level based on confidence
	result.ThreatLevel = td.calculateThreatLevel(result.Confidence)
	
	// Combine reasons
	result.Reason = td.combineReasons(reasons)
	
	// Add metadata
	result.Metadata["threat_score_count"] = len(threatScores)
	result.Metadata["max_threat_score"] = maxScore
	result.Metadata["analysis_methods"] = td.getUsedAnalysisMethods()
}

// applyThreatPolicies applies threat detection policies to determine final decision
func (td *DefaultThreatDetector) applyThreatPolicies(result *ThreatAnalysisResult) {
	// Check confidence threshold
	result.IsThreat = result.Confidence >= td.policies.ConfidenceThreshold
	
	// Check threat level thresholds
	if threshold, exists := td.policies.ThreatLevelThresholds[result.ThreatLevel]; exists {
		if result.Confidence < threshold {
			result.IsThreat = false
		}
	}
	
	// Determine recommended action based on threat type and level
	if result.IsThreat {
		if action, exists := td.policies.ActionPolicies[result.ThreatType]; exists {
			result.RecommendedAction = action
		} else {
			// Default action based on threat level
			switch result.ThreatLevel {
			case ThreatLevelCritical:
				result.RecommendedAction = ActionBlock
			case ThreatLevelHigh:
				result.RecommendedAction = ActionBlock
			case ThreatLevelMedium:
				result.RecommendedAction = ActionChallenge
			case ThreatLevelLow:
				result.RecommendedAction = ActionMonitor
			default:
				result.RecommendedAction = ActionAllow
			}
		}
	} else {
		result.RecommendedAction = ActionAllow
	}
	
	// Override for specific cases
	if result.ThreatType == ThreatTypeInsiderThreat {
		result.RecommendedAction = ActionAlert // Always alert for insider threats
	}
}

// updateStatistics updates threat detection statistics
func (td *DefaultThreatDetector) updateStatistics(result *ThreatAnalysisResult) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	if result.IsThreat {
		td.stats.ThreatsDetected++
		td.stats.ThreatsByType[result.ThreatType]++
		td.stats.ThreatsByLevel[result.ThreatLevel]++
		
		now := time.Now()
		td.stats.LastThreat = &now
	}
	
	td.stats.ActionsTaken[result.RecommendedAction]++
	
	// Update average confidence
	totalConfidence := td.stats.AverageConfidence * float64(td.stats.TotalRequests-1)
	td.stats.AverageConfidence = (totalConfidence + result.Confidence) / float64(td.stats.TotalRequests)
	
	// Update average processing time
	totalTime := td.stats.AverageProcessingTime * time.Duration(td.stats.TotalRequests-1)
	td.stats.AverageProcessingTime = (totalTime + result.ProcessingTime) / time.Duration(td.stats.TotalRequests)
	
	td.stats.LastUpdated = time.Now()
}

// UpdateModels updates ML models with new training data
func (td *DefaultThreatDetector) UpdateModels(ctx context.Context, trainingData []*TrainingExample) error {
	if td.contentModel == nil {
		return fmt.Errorf("content model not available")
	}
	
	td.logger.Infof("Updating models with %d training examples", len(trainingData))
	
	// Update content model
	if err := td.contentModel.Train(ctx, trainingData); err != nil {
		return fmt.Errorf("failed to update content model: %w", err)
	}
	
	// Update behavioral analyzer if learning is enabled
	if td.policies.BehavioralAnalysis {
		// Convert training examples to request contexts
		var requestContexts []*RequestContext
		for _, example := range trainingData {
			if requestContext := td.convertTrainingExampleToRequestContext(example); requestContext != nil {
				requestContexts = append(requestContexts, requestContext)
			}
		}
		
		if len(requestContexts) > 0 {
			if err := td.behavioralAnalyzer.TrainModel(ctx, requestContexts); err != nil {
				td.logger.Warnf("Failed to update behavioral model: %v", err)
			}
		}
	}
	
	// Update model accuracy statistics
	if metrics, err := td.contentModel.GetMetrics(ctx); err == nil {
		td.mu.Lock()
		td.stats.ModelAccuracy[td.contentModel.GetVersion()] = metrics.Accuracy
		td.mu.Unlock()
	}
	
	td.logger.Info("Model update completed")
	return nil
}

// GetThreatIntelligence retrieves threat intelligence for a query
func (td *DefaultThreatDetector) GetThreatIntelligence(ctx context.Context, query *ThreatQuery) (*ThreatIntelligence, error) {
	intelligence := &ThreatIntelligence{
		Query:     query,
		IsThreat:  false,
		Patterns:  make([]*ThreatPattern, 0),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}
	
	switch query.Type {
	case "domain":
		if pattern := td.checkDomainThreatIntelligence(query.Value); pattern != nil {
			intelligence.IsThreat = true
			intelligence.ThreatType = pattern.Type
			intelligence.Confidence = pattern.Confidence
			intelligence.Patterns = append(intelligence.Patterns, pattern)
		}
	case "ip":
		if pattern := td.checkIPThreatIntelligence(query.Value); pattern != nil {
			intelligence.IsThreat = true
			intelligence.ThreatType = pattern.Type
			intelligence.Confidence = pattern.Confidence
			intelligence.Patterns = append(intelligence.Patterns, pattern)
		}
	case "user_agent":
		if pattern := td.checkUserAgentPatterns(query.Value); pattern != nil {
			intelligence.IsThreat = true
			intelligence.ThreatType = pattern.Type
			intelligence.Confidence = pattern.Confidence
			intelligence.Patterns = append(intelligence.Patterns, pattern)
		}
	default:
		return nil, fmt.Errorf("unsupported query type: %s", query.Type)
	}
	
	return intelligence, nil
}

// ConfigurePolicies updates threat detection policies
func (td *DefaultThreatDetector) ConfigurePolicies(ctx context.Context, policies *ThreatPolicies) error {
	td.mu.Lock()
	td.policies = policies
	td.policies.UpdatedAt = time.Now()
	td.mu.Unlock()
	
	// Save to storage
	if err := td.storage.SaveThreatPolicies(ctx, policies); err != nil {
		return fmt.Errorf("failed to save threat policies: %w", err)
	}
	
	td.logger.Info("Threat detection policies updated")
	return nil
}

// GetStats returns current threat detection statistics
func (td *DefaultThreatDetector) GetStats(ctx context.Context) (*AIThreatStats, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	// Return a copy of stats
	statsCopy := *td.stats
	statsCopy.ThreatsByType = make(map[ThreatType]int64)
	statsCopy.ThreatsByLevel = make(map[ThreatLevel]int64)
	statsCopy.ActionsTaken = make(map[ActionType]int64)
	statsCopy.ModelAccuracy = make(map[string]float64)
	
	for k, v := range td.stats.ThreatsByType {
		statsCopy.ThreatsByType[k] = v
	}
	for k, v := range td.stats.ThreatsByLevel {
		statsCopy.ThreatsByLevel[k] = v
	}
	for k, v := range td.stats.ActionsTaken {
		statsCopy.ActionsTaken[k] = v
	}
	for k, v := range td.stats.ModelAccuracy {
		statsCopy.ModelAccuracy[k] = v
	}
	
	return &statsCopy, nil
}

// GetHealth returns health status of AI components
func (td *DefaultThreatDetector) GetHealth(ctx context.Context) (*AIHealthStatus, error) {
	health := &AIHealthStatus{
		Overall:         "healthy",
		Components:      make(map[string]string),
		ModelStatus:     make(map[string]string),
		LastHealthCheck: time.Now(),
		Issues:          make([]string, 0),
		Metrics:         make(map[string]interface{}),
	}
	
	// Check storage health
	if _, err := td.storage.LoadAIStats(ctx); err != nil {
		health.Components["storage"] = "unhealthy"
		health.Issues = append(health.Issues, fmt.Sprintf("Storage error: %v", err))
		health.Overall = "degraded"
	} else {
		health.Components["storage"] = "healthy"
	}
	
	// Check feature extractor health
	if td.featureExtractor != nil {
		health.Components["feature_extractor"] = "healthy"
	} else {
		health.Components["feature_extractor"] = "unavailable"
		health.Issues = append(health.Issues, "Feature extractor not available")
		health.Overall = "degraded"
	}
	
	// Check behavioral analyzer health
	if td.behavioralAnalyzer != nil {
		health.Components["behavioral_analyzer"] = "healthy"
	} else {
		health.Components["behavioral_analyzer"] = "unavailable"
		health.Issues = append(health.Issues, "Behavioral analyzer not available")
		health.Overall = "degraded"
	}
	
	// Check content model health
	if td.contentModel != nil && td.contentModel.IsReady() {
		health.ModelStatus["content_model"] = "ready"
	} else if td.contentModel != nil {
		health.ModelStatus["content_model"] = "not_ready"
		health.Issues = append(health.Issues, "Content model not ready")
		health.Overall = "degraded"
	} else {
		health.ModelStatus["content_model"] = "unavailable"
		health.Issues = append(health.Issues, "Content model not available")
		health.Overall = "degraded"
	}
	
	// Add metrics
	td.mu.RLock()
	health.Metrics["total_requests"] = td.stats.TotalRequests
	health.Metrics["threats_detected"] = td.stats.ThreatsDetected
	health.Metrics["average_processing_time"] = td.stats.AverageProcessingTime.Milliseconds()
	health.Metrics["policies_enabled"] = td.policies.GlobalEnabled
	td.mu.RUnlock()
	
	// Determine overall health
	if len(health.Issues) > 3 {
		health.Overall = "unhealthy"
	}
	
	return health, nil
}

// SetContentModel sets the content analysis model
func (td *DefaultThreatDetector) SetContentModel(model MLModel) {
	td.contentModel = model
	td.logger.Info("Content model updated")
}

// Helper methods

func (td *DefaultThreatDetector) getSubjectIdentifier(request *ThreatAnalysisRequest) string {
	if request.UserID != "" {
		return fmt.Sprintf("user:%s", request.UserID)
	}
	if request.SourceIP != nil {
		return fmt.Sprintf("ip:%s", request.SourceIP.String())
	}
	return "unknown"
}

func (td *DefaultThreatDetector) calculateThreatLevel(confidence float64) ThreatLevel {
	if confidence >= 0.9 {
		return ThreatLevelCritical
	} else if confidence >= 0.7 {
		return ThreatLevelHigh
	} else if confidence >= 0.5 {
		return ThreatLevelMedium
	}
	return ThreatLevelLow
}

func (td *DefaultThreatDetector) combineReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "No specific reason"
	}
	if len(reasons) == 1 {
		return reasons[0]
	}
	
	// Combine first few reasons
	combined := reasons[0]
	for i := 1; i < len(reasons) && i < 3; i++ {
		combined += "; " + reasons[i]
	}
	
	if len(reasons) > 3 {
		combined += fmt.Sprintf(" (and %d more)", len(reasons)-3)
	}
	
	return combined
}

func (td *DefaultThreatDetector) getUsedAnalysisMethods() []string {
	var methods []string
	
	if td.policies.MachineLearning && td.contentModel != nil {
		methods = append(methods, "machine_learning")
	}
	if td.policies.BehavioralAnalysis {
		methods = append(methods, "behavioral_analysis")
	}
	if td.policies.ThreatIntelligence {
		methods = append(methods, "threat_intelligence")
	}
	
	return methods
}

func (td *DefaultThreatDetector) convertTrainingExampleToRequestContext(example *TrainingExample) *RequestContext {
	// This is a simplified conversion - in practice, you'd need more sophisticated mapping
	return &RequestContext{
		Timestamp: example.Timestamp,
		UserID:    example.Source, // Use source as user ID for simplicity
	}
}

// Placeholder threat intelligence methods (would be implemented with real threat feeds)
func (td *DefaultThreatDetector) checkDomainThreatIntelligence(domain string) *ThreatPattern {
	// Placeholder implementation
	return nil
}

func (td *DefaultThreatDetector) checkIPThreatIntelligence(ip string) *ThreatPattern {
	// Placeholder implementation
	return nil
}

func (td *DefaultThreatDetector) checkUserAgentPatterns(userAgent string) *ThreatPattern {
	// Placeholder implementation
	return nil
}

// Utility functions
func extractPathFromURL(url string) string {
	// Simple path extraction - in practice, use url.Parse
	return url
}

func extractDomainFromURL(url string) string {
	// Simple domain extraction - in practice, use url.Parse
	return ""
}

func extractCountryFromContext(context map[string]interface{}) string {
	if context == nil {
		return ""
	}
	if country, ok := context["country"].(string); ok {
		return country
	}
	return ""
}

// Default configurations
func getDefaultThreatPolicies() *ThreatPolicies {
	return &ThreatPolicies{
		GlobalEnabled:       true,
		ConfidenceThreshold: 0.7,
		ThreatLevelThresholds: map[ThreatLevel]float64{
			ThreatLevelLow:      0.3,
			ThreatLevelMedium:   0.5,
			ThreatLevelHigh:     0.7,
			ThreatLevelCritical: 0.9,
		},
		ActionPolicies: map[ThreatType]ActionType{
			ThreatTypeMalware:          ActionBlock,
			ThreatTypePhishing:         ActionBlock,
			ThreatTypeBotnet:           ActionBlock,
			ThreatTypeDataExfiltration: ActionQuarantine,
			ThreatTypeCommandControl:   ActionBlock,
			ThreatTypeAnomalous:        ActionChallenge,
			ThreatTypeZeroDay:          ActionQuarantine,
			ThreatTypeInsiderThreat:    ActionAlert,
			ThreatTypeSuspicious:       ActionMonitor,
		},
		BehavioralAnalysis: true,
		MachineLearning:    true,
		ThreatIntelligence: true,
		AlertingEnabled:    true,
		AlertThreshold:     ThreatLevelMedium,
		UpdatedAt:          time.Now(),
	}
}

func getDefaultAIThreatStats() *AIThreatStats {
	return &AIThreatStats{
		ThreatsByType:         make(map[ThreatType]int64),
		ThreatsByLevel:        make(map[ThreatLevel]int64),
		ActionsTaken:          make(map[ActionType]int64),
		ModelAccuracy:         make(map[string]float64),
		AverageProcessingTime: 0,
		LastUpdated:           time.Now(),
	}
}