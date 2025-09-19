package models

import (
	"context"
	"testing"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContentAnalysisModel_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	assert.Equal(t, "content-analysis", model.name)
	assert.Equal(t, "1.0.0", model.GetVersion())
	assert.True(t, model.IsReady())
	assert.NotEmpty(t, model.rules)
	assert.NotEmpty(t, model.thresholds)
	assert.NotEmpty(t, model.weights)
}

func TestContentAnalysisModel_PredictMalware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Create features indicating malware
	features := map[string]float64{
		"url_entropy":     5.0,  // High entropy
		"suspicious_tld":  1.0,  // Suspicious TLD
		"has_ip_in_url":   1.0,  // IP in URL
		"content_length":  1024,
		"header_count":    5,
	}
	
	prediction, err := model.Predict(context.Background(), features)
	require.NoError(t, err)
	require.NotNil(t, prediction)
	
	assert.Equal(t, "content-analysis", prediction.ModelName)
	assert.Equal(t, "1.0.0", prediction.ModelVersion)
	assert.True(t, prediction.IsThreat)
	assert.Equal(t, ai.ThreatTypeMalware, prediction.ThreatType)
	assert.Greater(t, prediction.Confidence, 0.5)
	assert.NotNil(t, prediction.Metadata)
}

func TestContentAnalysisModel_PredictPhishing(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Create features indicating phishing
	features := map[string]float64{
		"domain_entropy":  4.0,  // High domain entropy
		"url_shortener":   1.0,  // URL shortener
		"has_homograph":   1.0,  // Homograph attack
		"content_length":  512,
		"header_count":    3,
	}
	
	prediction, err := model.Predict(context.Background(), features)
	require.NoError(t, err)
	require.NotNil(t, prediction)
	
	assert.True(t, prediction.IsThreat)
	assert.Equal(t, ai.ThreatTypePhishing, prediction.ThreatType)
	assert.Greater(t, prediction.Confidence, 0.5)
}

func TestContentAnalysisModel_PredictBenign(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Create features indicating benign content
	features := map[string]float64{
		"url_entropy":     2.5,  // Low entropy
		"suspicious_tld":  0.0,  // Normal TLD
		"has_ip_in_url":   0.0,  // Domain name
		"domain_entropy":  2.0,  // Low domain entropy
		"url_shortener":   0.0,  // Not a shortener
		"has_homograph":   0.0,  // No homograph
		"content_length":  1024,
		"header_count":    5,
	}
	
	prediction, err := model.Predict(context.Background(), features)
	require.NoError(t, err)
	require.NotNil(t, prediction)
	
	assert.False(t, prediction.IsThreat)
	assert.Less(t, prediction.Confidence, 0.7) // Should have low confidence for threat
}

func TestContentAnalysisModel_Training(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Create training examples
	examples := []*ai.TrainingExample{
		// Malware examples
		{
			ID: "malware-1",
			Features: map[string]float64{
				"url_entropy":    5.5,
				"suspicious_tld": 1.0,
				"has_ip_in_url":  1.0,
			},
			Label:      true,
			ThreatType: ai.ThreatTypeMalware,
			Source:     "manual",
			Timestamp:  time.Now(),
		},
		{
			ID: "malware-2",
			Features: map[string]float64{
				"url_entropy":    4.8,
				"suspicious_tld": 1.0,
				"has_ip_in_url":  0.0,
			},
			Label:      true,
			ThreatType: ai.ThreatTypeMalware,
			Source:     "manual",
			Timestamp:  time.Now(),
		},
		// Phishing examples
		{
			ID: "phishing-1",
			Features: map[string]float64{
				"domain_entropy": 4.2,
				"url_shortener":  1.0,
				"has_homograph":  1.0,
			},
			Label:      true,
			ThreatType: ai.ThreatTypePhishing,
			Source:     "manual",
			Timestamp:  time.Now(),
		},
		{
			ID: "phishing-2",
			Features: map[string]float64{
				"domain_entropy": 3.8,
				"url_shortener":  0.0,
				"has_homograph":  1.0,
			},
			Label:      true,
			ThreatType: ai.ThreatTypePhishing,
			Source:     "manual",
			Timestamp:  time.Now(),
		},
		// Benign examples
		{
			ID: "benign-1",
			Features: map[string]float64{
				"url_entropy":    2.5,
				"suspicious_tld": 0.0,
				"has_ip_in_url":  0.0,
				"domain_entropy": 2.0,
				"url_shortener":  0.0,
				"has_homograph":  0.0,
			},
			Label:     false,
			Source:    "manual",
			Timestamp: time.Now(),
		},
		{
			ID: "benign-2",
			Features: map[string]float64{
				"url_entropy":    3.0,
				"suspicious_tld": 0.0,
				"has_ip_in_url":  0.0,
				"domain_entropy": 2.5,
				"url_shortener":  0.0,
				"has_homograph":  0.0,
			},
			Label:     false,
			Source:    "manual",
			Timestamp: time.Now(),
		},
		// Add more examples to meet minimum requirements
		{
			ID: "benign-3",
			Features: map[string]float64{
				"url_entropy":    2.8,
				"suspicious_tld": 0.0,
				"has_ip_in_url":  0.0,
			},
			Label:     false,
			Source:    "automated",
			Timestamp: time.Now(),
		},
		{
			ID: "benign-4",
			Features: map[string]float64{
				"url_entropy":    3.2,
				"suspicious_tld": 0.0,
				"has_ip_in_url":  0.0,
			},
			Label:     false,
			Source:    "automated",
			Timestamp: time.Now(),
		},
	}
	
	// Train the model
	err := model.Train(context.Background(), examples)
	require.NoError(t, err)
	
	// Verify metrics were updated
	metrics, err := model.GetMetrics(context.Background())
	require.NoError(t, err)
	assert.Greater(t, metrics.Accuracy, 0.0)
	assert.NotZero(t, metrics.LastEvaluated)
}

func TestContentAnalysisModel_RuleManagement(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	initialRuleCount := len(model.GetRules())
	
	// Add a new rule
	newRule := &ContentRule{
		ID:     "test-rule",
		Name:   "Test Rule",
		Type:   ai.ThreatTypeSuspicious,
		Weight: 0.5,
		Features: []string{"test_feature"},
		Conditions: []*RuleCondition{
			{Feature: "test_feature", Operator: "gt", Value: 0.5},
		},
		Enabled: true,
	}
	
	err := model.AddRule(newRule)
	require.NoError(t, err)
	
	// Verify rule was added
	rules := model.GetRules()
	assert.Len(t, rules, initialRuleCount+1)
	
	// Find the added rule
	var foundRule *ContentRule
	for _, rule := range rules {
		if rule.ID == "test-rule" {
			foundRule = rule
			break
		}
	}
	require.NotNil(t, foundRule)
	assert.Equal(t, "Test Rule", foundRule.Name)
	assert.Equal(t, ai.ThreatTypeSuspicious, foundRule.Type)
	
	// Test duplicate rule ID
	err = model.AddRule(newRule)
	assert.Error(t, err)
	
	// Remove the rule
	err = model.RemoveRule("test-rule")
	require.NoError(t, err)
	
	// Verify rule was removed
	rules = model.GetRules()
	assert.Len(t, rules, initialRuleCount)
	
	// Test removing non-existent rule
	err = model.RemoveRule("non-existent")
	assert.Error(t, err)
}

func TestContentAnalysisModel_ThresholdManagement(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Test getting default threshold
	threshold := model.GetThreshold(ai.ThreatTypeMalware)
	assert.Equal(t, 0.7, threshold)
	
	// Test setting new threshold
	model.SetThreshold(ai.ThreatTypeMalware, 0.8)
	threshold = model.GetThreshold(ai.ThreatTypeMalware)
	assert.Equal(t, 0.8, threshold)
	
	// Test getting threshold for unknown threat type
	threshold = model.GetThreshold(ai.ThreatType("unknown"))
	assert.Equal(t, 0.5, threshold) // Default
}

func TestContentAnalysisModel_FeatureWeights(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Test getting feature weights
	weights := model.GetFeatureWeights()
	assert.NotEmpty(t, weights)
	assert.Contains(t, weights, "url_entropy")
	assert.Contains(t, weights, "suspicious_tld")
	
	// Test setting feature weight
	originalWeight := weights["url_entropy"]
	model.SetFeatureWeight("url_entropy", 0.95)
	
	updatedWeights := model.GetFeatureWeights()
	assert.Equal(t, 0.95, updatedWeights["url_entropy"])
	assert.NotEqual(t, originalWeight, updatedWeights["url_entropy"])
}

func TestContentAnalysisModel_RuleEvaluation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Create a test rule
	rule := &ContentRule{
		ID:     "test-eval-rule",
		Name:   "Test Evaluation Rule",
		Type:   ai.ThreatTypeMalware,
		Weight: 1.0,
		Features: []string{"url_entropy"},
		Conditions: []*RuleCondition{
			{Feature: "url_entropy", Operator: "gt", Value: 4.0},
			{Feature: "suspicious_tld", Operator: "eq", Value: 1.0},
		},
		Enabled: true,
	}
	
	// Test features that meet all conditions
	features1 := map[string]float64{
		"url_entropy":    5.0,
		"suspicious_tld": 1.0,
	}
	score1 := model.evaluateRule(rule, features1)
	assert.Greater(t, score1, 0.0)
	
	// Test features that meet some conditions
	features2 := map[string]float64{
		"url_entropy":    5.0,
		"suspicious_tld": 0.0,
	}
	score2 := model.evaluateRule(rule, features2)
	assert.Greater(t, score2, 0.0)
	assert.Less(t, score2, score1) // Should be lower than full match
	
	// Test features that meet no conditions
	features3 := map[string]float64{
		"url_entropy":    2.0,
		"suspicious_tld": 0.0,
	}
	score3 := model.evaluateRule(rule, features3)
	assert.Greater(t, score3, 0.0) // Still has feature-based scoring
}

func TestContentAnalysisModel_ConditionEvaluation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	features := map[string]float64{
		"test_feature": 5.0,
	}
	
	tests := []struct {
		name      string
		condition *RuleCondition
		expected  bool
	}{
		{
			name:      "greater than - true",
			condition: &RuleCondition{Feature: "test_feature", Operator: "gt", Value: 4.0},
			expected:  true,
		},
		{
			name:      "greater than - false",
			condition: &RuleCondition{Feature: "test_feature", Operator: "gt", Value: 6.0},
			expected:  false,
		},
		{
			name:      "less than - true",
			condition: &RuleCondition{Feature: "test_feature", Operator: "lt", Value: 6.0},
			expected:  true,
		},
		{
			name:      "less than - false",
			condition: &RuleCondition{Feature: "test_feature", Operator: "lt", Value: 4.0},
			expected:  false,
		},
		{
			name:      "equal - true",
			condition: &RuleCondition{Feature: "test_feature", Operator: "eq", Value: 5.0},
			expected:  true,
		},
		{
			name:      "equal - false",
			condition: &RuleCondition{Feature: "test_feature", Operator: "eq", Value: 4.0},
			expected:  false,
		},
		{
			name:      "greater than or equal - true",
			condition: &RuleCondition{Feature: "test_feature", Operator: "gte", Value: 5.0},
			expected:  true,
		},
		{
			name:      "less than or equal - true",
			condition: &RuleCondition{Feature: "test_feature", Operator: "lte", Value: 5.0},
			expected:  true,
		},
		{
			name:      "unknown operator",
			condition: &RuleCondition{Feature: "test_feature", Operator: "unknown", Value: 5.0},
			expected:  false,
		},
		{
			name:      "missing feature",
			condition: &RuleCondition{Feature: "missing_feature", Operator: "gt", Value: 1.0},
			expected:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := model.evaluateCondition(tt.condition, features)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContentAnalysisModel_ValidationErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewContentAnalysisModel(logger)
	
	// Test prediction with invalid features
	_, err := model.Predict(context.Background(), nil)
	assert.Error(t, err)
	
	_, err = model.Predict(context.Background(), map[string]float64{})
	assert.Error(t, err)
	
	// Test training with invalid data
	err = model.Train(context.Background(), nil)
	assert.Error(t, err)
	
	err = model.Train(context.Background(), []*ai.TrainingExample{})
	assert.Error(t, err)
	
	// Test adding invalid rule
	err = model.AddRule(&ContentRule{})
	assert.Error(t, err)
}