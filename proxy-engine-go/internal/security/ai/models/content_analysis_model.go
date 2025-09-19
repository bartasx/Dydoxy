package models

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/sirupsen/logrus"
)

// ContentAnalysisModel implements threat detection for web content
type ContentAnalysisModel struct {
	*BaseModel
	rules           []*ContentRule
	weights         map[string]float64
	thresholds      map[ai.ThreatType]float64
	utils           *ModelUtils
}

// ContentRule represents a rule for content analysis
type ContentRule struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Type        ai.ThreatType    `json:"type"`
	Pattern     string           `json:"pattern"`
	Weight      float64          `json:"weight"`
	Features    []string         `json:"features"`
	Conditions  []*RuleCondition `json:"conditions"`
	Enabled     bool             `json:"enabled"`
}

// RuleCondition represents a condition within a rule
type RuleCondition struct {
	Feature   string  `json:"feature"`
	Operator  string  `json:"operator"` // gt, lt, eq, contains, regex
	Value     float64 `json:"value"`
	StringVal string  `json:"string_val,omitempty"`
}

// NewContentAnalysisModel creates a new content analysis model
func NewContentAnalysisModel(logger *logrus.Logger) *ContentAnalysisModel {
	baseModel := NewBaseModel("content-analysis", "1.0.0", "content", "Content threat detection model", logger)
	
	model := &ContentAnalysisModel{
		BaseModel:  baseModel,
		rules:      make([]*ContentRule, 0),
		weights:    make(map[string]float64),
		thresholds: make(map[ai.ThreatType]float64),
		utils:      NewModelUtils(),
	}
	
	// Initialize default rules and thresholds
	model.initializeDefaultRules()
	model.initializeDefaultThresholds()
	model.initializeFeatureWeights()
	
	model.SetReady(true)
	return model
}

// Predict performs threat prediction on content features
func (m *ContentAnalysisModel) Predict(ctx context.Context, features map[string]float64) (*ai.MLPrediction, error) {
	if err := m.ValidateFeatures(features); err != nil {
		return nil, fmt.Errorf("feature validation failed: %w", err)
	}
	
	// Calculate threat scores for each threat type
	threatScores := make(map[ai.ThreatType]float64)
	
	for _, rule := range m.rules {
		if !rule.Enabled {
			continue
		}
		
		score := m.evaluateRule(rule, features)
		if score > 0 {
			threatScores[rule.Type] += score * rule.Weight
		}
	}
	
	// Find the highest scoring threat type
	var maxThreatType ai.ThreatType
	var maxScore float64
	
	for threatType, score := range threatScores {
		if score > maxScore {
			maxScore = score
			maxThreatType = threatType
		}
	}
	
	// Determine if this is a threat based on threshold
	threshold := m.thresholds[maxThreatType]
	if threshold == 0 {
		threshold = 0.5 // Default threshold
	}
	
	isThreat := maxScore >= threshold
	confidence := m.utils.CalculateConfidence(maxScore)
	
	prediction := &ai.MLPrediction{
		ModelName:    m.name,
		ModelVersion: m.version,
		IsThreat:     isThreat,
		Confidence:   confidence,
		ThreatType:   maxThreatType,
		Features:     features,
		Metadata: map[string]interface{}{
			"threat_scores": threatScores,
			"max_score":     maxScore,
			"threshold":     threshold,
		},
		Timestamp: time.Now(),
	}
	
	m.LogPrediction(prediction, features)
	return prediction, nil
}

// Train updates the model with new training data
func (m *ContentAnalysisModel) Train(ctx context.Context, examples []*ai.TrainingExample) error {
	if err := m.utils.ValidateTrainingData(examples); err != nil {
		return fmt.Errorf("training data validation failed: %w", err)
	}
	
	m.logger.Infof("Training content analysis model with %d examples", len(examples))
	
	// Split data into train and validation sets
	trainData, validationData, err := m.utils.SplitTrainingData(examples, 0.8)
	if err != nil {
		return fmt.Errorf("failed to split training data: %w", err)
	}
	
	// Balance training data
	trainData = m.utils.BalanceTrainingData(trainData)
	
	// Update feature weights based on training data
	if err := m.updateFeatureWeights(trainData); err != nil {
		m.logger.Warnf("Failed to update feature weights: %v", err)
	}
	
	// Update thresholds based on validation data
	if err := m.updateThresholds(validationData); err != nil {
		m.logger.Warnf("Failed to update thresholds: %v", err)
	}
	
	// Evaluate model performance
	metrics, err := m.utils.EvaluateModel(ctx, m, validationData)
	if err != nil {
		return fmt.Errorf("model evaluation failed: %w", err)
	}
	
	m.UpdateMetrics(metrics)
	m.logger.Infof("Model training completed - Accuracy: %.3f, Precision: %.3f, Recall: %.3f", 
		metrics.Accuracy, metrics.Precision, metrics.Recall)
	
	return nil
}

// evaluateRule evaluates a single rule against features
func (m *ContentAnalysisModel) evaluateRule(rule *ContentRule, features map[string]float64) float64 {
	score := 0.0
	conditionsMet := 0
	
	for _, condition := range rule.Conditions {
		if m.evaluateCondition(condition, features) {
			conditionsMet++
		}
	}
	
	if len(rule.Conditions) > 0 {
		// Score based on percentage of conditions met
		score = float64(conditionsMet) / float64(len(rule.Conditions))
	}
	
	// Apply feature-based scoring
	for _, featureName := range rule.Features {
		if value, exists := features[featureName]; exists {
			weight := m.weights[featureName]
			if weight == 0 {
				weight = 1.0
			}
			score += value * weight
		}
	}
	
	// Normalize score to [0, 1] range
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// evaluateCondition evaluates a single condition
func (m *ContentAnalysisModel) evaluateCondition(condition *RuleCondition, features map[string]float64) bool {
	value, exists := features[condition.Feature]
	if !exists {
		return false
	}
	
	switch condition.Operator {
	case "gt":
		return value > condition.Value
	case "lt":
		return value < condition.Value
	case "eq":
		return math.Abs(value-condition.Value) < 0.001
	case "gte":
		return value >= condition.Value
	case "lte":
		return value <= condition.Value
	default:
		return false
	}
}

// updateFeatureWeights updates feature weights based on training data
func (m *ContentAnalysisModel) updateFeatureWeights(examples []*ai.TrainingExample) error {
	importance, err := m.utils.GetFeatureImportance(examples)
	if err != nil {
		return err
	}
	
	// Normalize importance scores
	maxImportance := 0.0
	for _, imp := range importance {
		if imp > maxImportance {
			maxImportance = imp
		}
	}
	
	if maxImportance > 0 {
		for feature, imp := range importance {
			m.weights[feature] = imp / maxImportance
		}
	}
	
	return nil
}

// updateThresholds updates threat type thresholds based on validation data
func (m *ContentAnalysisModel) updateThresholds(examples []*ai.TrainingExample) error {
	// Group examples by threat type
	threatExamples := make(map[ai.ThreatType][]*ai.TrainingExample)
	
	for _, example := range examples {
		if example.Label {
			threatType := example.ThreatType
			if threatType == "" {
				threatType = ai.ThreatTypeSuspicious // Default threat type
			}
			threatExamples[threatType] = append(threatExamples[threatType], example)
		}
	}
	
	// Calculate optimal thresholds for each threat type
	for threatType, typeExamples := range threatExamples {
		if len(typeExamples) < 5 {
			continue // Need minimum examples to calculate threshold
		}
		
		var scores []float64
		for _, example := range typeExamples {
			prediction, err := m.Predict(context.Background(), example.Features)
			if err != nil {
				continue
			}
			scores = append(scores, prediction.Confidence)
		}
		
		if len(scores) > 0 {
			sort.Float64s(scores)
			// Use 25th percentile as threshold to minimize false negatives
			thresholdIndex := len(scores) / 4
			if thresholdIndex < len(scores) {
				m.thresholds[threatType] = scores[thresholdIndex]
			}
		}
	}
	
	return nil
}

// initializeDefaultRules sets up default content analysis rules
func (m *ContentAnalysisModel) initializeDefaultRules() {
	m.rules = []*ContentRule{
		{
			ID:     "malware-url-patterns",
			Name:   "Malware URL Patterns",
			Type:   ai.ThreatTypeMalware,
			Weight: 0.9,
			Features: []string{"url_entropy", "suspicious_tld", "has_ip_in_url"},
			Conditions: []*RuleCondition{
				{Feature: "url_entropy", Operator: "gt", Value: 4.5},
				{Feature: "suspicious_tld", Operator: "eq", Value: 1.0},
				{Feature: "has_ip_in_url", Operator: "eq", Value: 1.0},
			},
			Enabled: true,
		},
		{
			ID:     "phishing-indicators",
			Name:   "Phishing Indicators",
			Type:   ai.ThreatTypePhishing,
			Weight: 0.85,
			Features: []string{"domain_entropy", "url_shortener", "has_homograph"},
			Conditions: []*RuleCondition{
				{Feature: "url_shortener", Operator: "eq", Value: 1.0},
				{Feature: "has_homograph", Operator: "eq", Value: 1.0},
				{Feature: "domain_entropy", Operator: "gt", Value: 3.5},
			},
			Enabled: true,
		},
		{
			ID:     "botnet-communication",
			Name:   "Botnet Communication",
			Type:   ai.ThreatTypeBotnet,
			Weight: 0.8,
			Features: []string{"likely_dga", "unusual_headers", "ua_suspicious"},
			Conditions: []*RuleCondition{
				{Feature: "likely_dga", Operator: "eq", Value: 1.0},
				{Feature: "unusual_headers", Operator: "gt", Value: 3.0},
				{Feature: "ua_suspicious", Operator: "eq", Value: 1.0},
			},
			Enabled: true,
		},
		{
			ID:     "data-exfiltration",
			Name:   "Data Exfiltration",
			Type:   ai.ThreatTypeDataExfiltration,
			Weight: 0.75,
			Features: []string{"content_length", "has_base64", "has_hex"},
			Conditions: []*RuleCondition{
				{Feature: "content_length", Operator: "gt", Value: 100000},
				{Feature: "has_base64", Operator: "eq", Value: 1.0},
				{Feature: "has_hex", Operator: "eq", Value: 1.0},
			},
			Enabled: true,
		},
		{
			ID:     "command-control",
			Name:   "Command & Control",
			Type:   ai.ThreatTypeCommandControl,
			Weight: 0.8,
			Features: []string{"is_night", "unusual_headers", "path_suspicious_keywords"},
			Conditions: []*RuleCondition{
				{Feature: "is_night", Operator: "eq", Value: 1.0},
				{Feature: "unusual_headers", Operator: "gt", Value: 2.0},
				{Feature: "path_suspicious_keywords", Operator: "gt", Value: 1.0},
			},
			Enabled: true,
		},
		{
			ID:     "zero-day-indicators",
			Name:   "Zero-Day Indicators",
			Type:   ai.ThreatTypeZeroDay,
			Weight: 0.7,
			Features: []string{"body_entropy", "has_encoded_chars", "query_entropy"},
			Conditions: []*RuleCondition{
				{Feature: "body_entropy", Operator: "gt", Value: 6.0},
				{Feature: "has_encoded_chars", Operator: "eq", Value: 1.0},
				{Feature: "query_entropy", Operator: "gt", Value: 5.0},
			},
			Enabled: true,
		},
	}
}

// initializeDefaultThresholds sets up default threat type thresholds
func (m *ContentAnalysisModel) initializeDefaultThresholds() {
	m.thresholds = map[ai.ThreatType]float64{
		ai.ThreatTypeMalware:          0.7,
		ai.ThreatTypePhishing:         0.6,
		ai.ThreatTypeBotnet:           0.75,
		ai.ThreatTypeDataExfiltration: 0.8,
		ai.ThreatTypeCommandControl:   0.7,
		ai.ThreatTypeZeroDay:          0.85,
		ai.ThreatTypeSuspicious:       0.5,
	}
}

// initializeFeatureWeights sets up default feature weights
func (m *ContentAnalysisModel) initializeFeatureWeights() {
	m.weights = map[string]float64{
		// URL features
		"url_length":         0.3,
		"url_entropy":        0.8,
		"domain_entropy":     0.7,
		"subdomain_count":    0.4,
		"path_depth":         0.3,
		"query_param_count":  0.2,
		
		// Content features
		"content_length":     0.5,
		"header_count":       0.3,
		"body_entropy":       0.6,
		
		// Suspicious indicators
		"suspicious_tld":     0.9,
		"has_ip_in_url":      0.8,
		"url_shortener":      0.7,
		"has_homograph":      0.8,
		"likely_dga":         0.9,
		"ua_suspicious":      0.6,
		"has_base64":         0.7,
		"has_hex":            0.6,
		"has_sql_keywords":   0.8,
		"has_xss":            0.8,
		"has_traversal":      0.9,
		"has_encoded_chars":  0.5,
		
		// Behavioral features
		"is_night":           0.4,
		"is_weekend":         0.3,
		"unusual_headers":    0.6,
		"path_suspicious_keywords": 0.7,
		"query_entropy":      0.5,
	}
}

// AddRule adds a new content analysis rule
func (m *ContentAnalysisModel) AddRule(rule *ContentRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	
	// Check for duplicate ID
	for _, existingRule := range m.rules {
		if existingRule.ID == rule.ID {
			return fmt.Errorf("rule with ID %s already exists", rule.ID)
		}
	}
	
	m.rules = append(m.rules, rule)
	m.logger.Infof("Added content analysis rule: %s", rule.Name)
	return nil
}

// RemoveRule removes a content analysis rule
func (m *ContentAnalysisModel) RemoveRule(ruleID string) error {
	for i, rule := range m.rules {
		if rule.ID == ruleID {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.logger.Infof("Removed content analysis rule: %s", rule.Name)
			return nil
		}
	}
	return fmt.Errorf("rule with ID %s not found", ruleID)
}

// GetRules returns all content analysis rules
func (m *ContentAnalysisModel) GetRules() []*ContentRule {
	rules := make([]*ContentRule, len(m.rules))
	copy(rules, m.rules)
	return rules
}

// SetThreshold sets the threshold for a threat type
func (m *ContentAnalysisModel) SetThreshold(threatType ai.ThreatType, threshold float64) {
	m.thresholds[threatType] = threshold
	m.logger.Infof("Set threshold for %s to %.3f", threatType, threshold)
}

// GetThreshold gets the threshold for a threat type
func (m *ContentAnalysisModel) GetThreshold(threatType ai.ThreatType) float64 {
	if threshold, exists := m.thresholds[threatType]; exists {
		return threshold
	}
	return 0.5 // Default threshold
}

// GetFeatureWeights returns current feature weights
func (m *ContentAnalysisModel) GetFeatureWeights() map[string]float64 {
	weights := make(map[string]float64)
	for k, v := range m.weights {
		weights[k] = v
	}
	return weights
}

// SetFeatureWeight sets the weight for a specific feature
func (m *ContentAnalysisModel) SetFeatureWeight(feature string, weight float64) {
	m.weights[feature] = weight
	m.logger.Debugf("Set weight for feature %s to %.3f", feature, weight)
}