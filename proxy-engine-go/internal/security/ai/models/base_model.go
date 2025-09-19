package models

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/sirupsen/logrus"
)

// BaseModel provides common functionality for ML models
type BaseModel struct {
	name         string
	version      string
	modelType    string
	description  string
	createdAt    time.Time
	updatedAt    time.Time
	isReady      bool
	metrics      *ai.ModelMetrics
	metadata     map[string]interface{}
	logger       *logrus.Logger
	mu           sync.RWMutex
}

// NewBaseModel creates a new base model
func NewBaseModel(name, version, modelType, description string, logger *logrus.Logger) *BaseModel {
	return &BaseModel{
		name:        name,
		version:     version,
		modelType:   modelType,
		description: description,
		createdAt:   time.Now(),
		updatedAt:   time.Now(),
		isReady:     false,
		metrics:     &ai.ModelMetrics{},
		metadata:    make(map[string]interface{}),
		logger:      logger,
	}
}

// GetVersion returns the model version
func (m *BaseModel) GetVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// IsReady returns true if the model is ready for inference
func (m *BaseModel) IsReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isReady
}

// GetMetrics returns model performance metrics
func (m *BaseModel) GetMetrics(ctx context.Context) (*ai.ModelMetrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return a copy of metrics
	metricsCopy := *m.metrics
	return &metricsCopy, nil
}

// Export exports the model for backup or deployment
func (m *BaseModel) Export(ctx context.Context) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	exportData := map[string]interface{}{
		"name":        m.name,
		"version":     m.version,
		"type":        m.modelType,
		"description": m.description,
		"created_at":  m.createdAt,
		"updated_at":  m.updatedAt,
		"metrics":     m.metrics,
		"metadata":    m.metadata,
	}
	
	data, err := json.Marshal(exportData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal model data: %w", err)
	}
	
	return data, nil
}

// Import imports a model from backup
func (m *BaseModel) Import(ctx context.Context, data []byte) error {
	var importData map[string]interface{}
	if err := json.Unmarshal(data, &importData); err != nil {
		return fmt.Errorf("failed to unmarshal model data: %w", err)
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Update model metadata
	if name, ok := importData["name"].(string); ok {
		m.name = name
	}
	if version, ok := importData["version"].(string); ok {
		m.version = version
	}
	if modelType, ok := importData["type"].(string); ok {
		m.modelType = modelType
	}
	if description, ok := importData["description"].(string); ok {
		m.description = description
	}
	
	// Parse timestamps
	if createdAtStr, ok := importData["created_at"].(string); ok {
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			m.createdAt = createdAt
		}
	}
	if updatedAtStr, ok := importData["updated_at"].(string); ok {
		if updatedAt, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			m.updatedAt = updatedAt
		}
	}
	
	// Import metrics
	if metricsData, ok := importData["metrics"].(map[string]interface{}); ok {
		if err := m.importMetrics(metricsData); err != nil {
			m.logger.Warnf("Failed to import metrics: %v", err)
		}
	}
	
	// Import metadata
	if metadata, ok := importData["metadata"].(map[string]interface{}); ok {
		m.metadata = metadata
	}
	
	m.updatedAt = time.Now()
	m.logger.Infof("Imported model %s version %s", m.name, m.version)
	
	return nil
}

// UpdateMetrics updates model performance metrics
func (m *BaseModel) UpdateMetrics(metrics *ai.ModelMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.metrics = metrics
	m.updatedAt = time.Now()
}

// SetReady sets the model ready status
func (m *BaseModel) SetReady(ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.isReady = ready
	if ready {
		m.logger.Infof("Model %s version %s is ready", m.name, m.version)
	}
}

// GetInfo returns model information
func (m *BaseModel) GetInfo() *ai.ModelInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return &ai.ModelInfo{
		Name:        m.name,
		Version:     m.version,
		Type:        m.modelType,
		Description: m.description,
		CreatedAt:   m.createdAt,
		UpdatedAt:   m.updatedAt,
		IsActive:    m.isReady,
		Metrics:     m.metrics,
	}
}

// SetMetadata sets metadata for the model
func (m *BaseModel) SetMetadata(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.metadata[key] = value
	m.updatedAt = time.Now()
}

// GetMetadata gets metadata from the model
func (m *BaseModel) GetMetadata(key string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	value, exists := m.metadata[key]
	return value, exists
}

// ValidateFeatures validates input features for the model
func (m *BaseModel) ValidateFeatures(features map[string]float64) error {
	if features == nil {
		return fmt.Errorf("features cannot be nil")
	}
	
	if len(features) == 0 {
		return fmt.Errorf("features cannot be empty")
	}
	
	// Check for NaN or infinite values
	for name, value := range features {
		if value != value { // NaN check
			return fmt.Errorf("feature %s has NaN value", name)
		}
		if value == value+1 && value == value*2 { // Infinity check
			return fmt.Errorf("feature %s has infinite value", name)
		}
	}
	
	return nil
}

// LogPrediction logs a prediction for monitoring and debugging
func (m *BaseModel) LogPrediction(prediction *ai.MLPrediction, features map[string]float64) {
	m.logger.WithFields(logrus.Fields{
		"model_name":    m.name,
		"model_version": m.version,
		"is_threat":     prediction.IsThreat,
		"confidence":    prediction.Confidence,
		"threat_type":   prediction.ThreatType,
		"feature_count": len(features),
	}).Debug("Model prediction completed")
}

// UpdateTrainingMetrics updates metrics after training
func (m *BaseModel) UpdateTrainingMetrics(accuracy, precision, recall, f1Score float64, 
	truePositives, falsePositives, trueNegatives, falseNegatives int64) {
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.metrics = &ai.ModelMetrics{
		Accuracy:       accuracy,
		Precision:      precision,
		Recall:         recall,
		F1Score:        f1Score,
		TruePositives:  truePositives,
		FalsePositives: falsePositives,
		TrueNegatives:  trueNegatives,
		FalseNegatives: falseNegatives,
		LastEvaluated:  time.Now(),
	}
	
	m.updatedAt = time.Now()
	
	m.logger.WithFields(logrus.Fields{
		"model_name":    m.name,
		"model_version": m.version,
		"accuracy":      accuracy,
		"precision":     precision,
		"recall":        recall,
		"f1_score":      f1Score,
	}).Info("Model training metrics updated")
}

// importMetrics imports metrics from map data
func (m *BaseModel) importMetrics(data map[string]interface{}) error {
	metrics := &ai.ModelMetrics{}
	
	if accuracy, ok := data["accuracy"].(float64); ok {
		metrics.Accuracy = accuracy
	}
	if precision, ok := data["precision"].(float64); ok {
		metrics.Precision = precision
	}
	if recall, ok := data["recall"].(float64); ok {
		metrics.Recall = recall
	}
	if f1Score, ok := data["f1_score"].(float64); ok {
		metrics.F1Score = f1Score
	}
	if truePositives, ok := data["true_positives"].(float64); ok {
		metrics.TruePositives = int64(truePositives)
	}
	if falsePositives, ok := data["false_positives"].(float64); ok {
		metrics.FalsePositives = int64(falsePositives)
	}
	if trueNegatives, ok := data["true_negatives"].(float64); ok {
		metrics.TrueNegatives = int64(trueNegatives)
	}
	if falseNegatives, ok := data["false_negatives"].(float64); ok {
		metrics.FalseNegatives = int64(falseNegatives)
	}
	if lastEvaluatedStr, ok := data["last_evaluated"].(string); ok {
		if lastEvaluated, err := time.Parse(time.RFC3339, lastEvaluatedStr); err == nil {
			metrics.LastEvaluated = lastEvaluated
		}
	}
	
	m.metrics = metrics
	return nil
}