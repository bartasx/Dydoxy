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

func TestBaseModel_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	assert.Equal(t, "test-model", model.name)
	assert.Equal(t, "1.0.0", model.GetVersion())
	assert.Equal(t, "test", model.modelType)
	assert.Equal(t, "Test model", model.description)
	assert.False(t, model.IsReady())
	assert.NotNil(t, model.metrics)
	assert.NotNil(t, model.metadata)
}

func TestBaseModel_ReadyStatus(t *testing.T) {
	logger := logrus.New()
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	assert.False(t, model.IsReady())
	
	model.SetReady(true)
	assert.True(t, model.IsReady())
	
	model.SetReady(false)
	assert.False(t, model.IsReady())
}

func TestBaseModel_Metrics(t *testing.T) {
	logger := logrus.New()
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	// Test initial metrics
	metrics, err := model.GetMetrics(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, 0.0, metrics.Accuracy)
	
	// Test updating metrics
	model.UpdateTrainingMetrics(0.95, 0.92, 0.88, 0.90, 100, 8, 85, 12)
	
	metrics, err = model.GetMetrics(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0.95, metrics.Accuracy)
	assert.Equal(t, 0.92, metrics.Precision)
	assert.Equal(t, 0.88, metrics.Recall)
	assert.Equal(t, 0.90, metrics.F1Score)
	assert.Equal(t, int64(100), metrics.TruePositives)
	assert.Equal(t, int64(8), metrics.FalsePositives)
	assert.Equal(t, int64(85), metrics.TrueNegatives)
	assert.Equal(t, int64(12), metrics.FalseNegatives)
}

func TestBaseModel_Metadata(t *testing.T) {
	logger := logrus.New()
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	// Test setting and getting metadata
	model.SetMetadata("training_data_size", 1000)
	model.SetMetadata("algorithm", "random_forest")
	
	value, exists := model.GetMetadata("training_data_size")
	assert.True(t, exists)
	assert.Equal(t, 1000, value)
	
	value, exists = model.GetMetadata("algorithm")
	assert.True(t, exists)
	assert.Equal(t, "random_forest", value)
	
	_, exists = model.GetMetadata("nonexistent")
	assert.False(t, exists)
}

func TestBaseModel_ExportImport(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create and configure original model
	original := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	original.SetReady(true)
	original.SetMetadata("test_key", "test_value")
	original.UpdateTrainingMetrics(0.95, 0.92, 0.88, 0.90, 100, 8, 85, 12)
	
	// Export model
	data, err := original.Export(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	
	// Create new model and import
	imported := NewBaseModel("", "", "", "", logger)
	err = imported.Import(context.Background(), data)
	require.NoError(t, err)
	
	// Verify imported data
	assert.Equal(t, "test-model", imported.name)
	assert.Equal(t, "1.0.0", imported.GetVersion())
	assert.Equal(t, "test", imported.modelType)
	assert.Equal(t, "Test model", imported.description)
	
	value, exists := imported.GetMetadata("test_key")
	assert.True(t, exists)
	assert.Equal(t, "test_value", value)
	
	metrics, err := imported.GetMetrics(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0.95, metrics.Accuracy)
}

func TestBaseModel_ValidateFeatures(t *testing.T) {
	logger := logrus.New()
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	tests := []struct {
		name        string
		features    map[string]float64
		expectError bool
	}{
		{
			name:        "nil features",
			features:    nil,
			expectError: true,
		},
		{
			name:        "empty features",
			features:    map[string]float64{},
			expectError: true,
		},
		{
			name: "valid features",
			features: map[string]float64{
				"feature1": 1.0,
				"feature2": 0.5,
				"feature3": -0.2,
			},
			expectError: false,
		},
		{
			name: "NaN feature",
			features: map[string]float64{
				"feature1": 1.0,
				"feature2": 0.0 / 0.0, // NaN
			},
			expectError: true,
		},
		{
			name: "infinite feature",
			features: map[string]float64{
				"feature1": 1.0,
				"feature2": 1.0 / 0.0, // +Inf
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := model.ValidateFeatures(tt.features)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBaseModel_GetInfo(t *testing.T) {
	logger := logrus.New()
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	model.SetReady(true)
	model.UpdateTrainingMetrics(0.95, 0.92, 0.88, 0.90, 100, 8, 85, 12)
	
	info := model.GetInfo()
	
	assert.Equal(t, "test-model", info.Name)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "test", info.Type)
	assert.Equal(t, "Test model", info.Description)
	assert.True(t, info.IsActive)
	assert.NotNil(t, info.Metrics)
	assert.Equal(t, 0.95, info.Metrics.Accuracy)
}

func TestBaseModel_LogPrediction(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	prediction := &ai.MLPrediction{
		ModelName:    "test-model",
		ModelVersion: "1.0.0",
		IsThreat:     true,
		Confidence:   0.85,
		ThreatType:   ai.ThreatTypeMalware,
		Timestamp:    time.Now(),
	}
	
	features := map[string]float64{
		"feature1": 1.0,
		"feature2": 0.5,
	}
	
	// This should not panic or error
	model.LogPrediction(prediction, features)
}

func TestBaseModel_ConcurrentAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	model := NewBaseModel("test-model", "1.0.0", "test", "Test model", logger)
	
	// Test concurrent access to model state
	done := make(chan bool, 10)
	
	// Concurrent readers
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = model.GetVersion()
				_ = model.IsReady()
				_, _ = model.GetMetrics(context.Background())
			}
			done <- true
		}()
	}
	
	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				model.SetReady(j%2 == 0)
				model.SetMetadata(fmt.Sprintf("key_%d", id), j)
				model.UpdateTrainingMetrics(0.9, 0.8, 0.7, 0.75, int64(j), int64(j+1), int64(j+2), int64(j+3))
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Verify model is still in a valid state
	assert.NotEmpty(t, model.GetVersion())
	metrics, err := model.GetMetrics(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
}