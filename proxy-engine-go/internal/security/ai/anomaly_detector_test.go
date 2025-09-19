package ai

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnomalyDetector_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.config)
	assert.True(t, detector.config.EnableEnsemble)
	assert.Equal(t, 0.7, detector.config.StatisticalThreshold)
}

func TestAnomalyDetector_StatisticalAnomalies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Create historical data with normal distribution around 50
	values := []float64{45, 48, 50, 52, 55, 47, 49, 51, 53, 46}
	timestamps := make([]time.Time, len(values))
	for i := range timestamps {
		timestamps[i] = time.Now().Add(-time.Duration(len(values)-i) * time.Hour)
	}
	
	historical := detector.BuildHistoricalData(values, timestamps)
	
	// Test normal value
	result, err := detector.DetectStatisticalAnomalies(context.Background(), 50.0, historical)
	require.NoError(t, err)
	assert.False(t, result.IsAnomalous)
	assert.Less(t, result.AnomalyScore, 0.7)
	
	// Test anomalous value (far from mean)
	result, err = detector.DetectStatisticalAnomalies(context.Background(), 100.0, historical)
	require.NoError(t, err)
	assert.True(t, result.IsAnomalous)
	assert.Greater(t, result.AnomalyScore, 0.7)
	assert.NotEmpty(t, result.AnomalyReasons)
	assert.Contains(t, result.FeatureScores, "z_score")
}

func TestAnomalyDetector_InsufficientData(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Create insufficient historical data
	values := []float64{50, 52} // Less than MinSamplesForStats
	timestamps := []time.Time{time.Now().Add(-2 * time.Hour), time.Now().Add(-1 * time.Hour)}
	
	historical := detector.BuildHistoricalData(values, timestamps)
	
	result, err := detector.DetectStatisticalAnomalies(context.Background(), 100.0, historical)
	require.NoError(t, err)
	assert.False(t, result.IsAnomalous)
	assert.Equal(t, 0.0, result.AnomalyScore)
	assert.Equal(t, 0.0, result.Confidence)
}

func TestAnomalyDetector_IsolationAnomalies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Create historical feature data (normal behavior)
	historicalFeatures := []map[string]float64{
		{"feature1": 10.0, "feature2": 20.0},
		{"feature1": 12.0, "feature2": 22.0},
		{"feature1": 11.0, "feature2": 21.0},
		{"feature1": 13.0, "feature2": 23.0},
		{"feature1": 9.0, "feature2": 19.0},
		{"feature1": 14.0, "feature2": 24.0},
		{"feature1": 10.5, "feature2": 20.5},
		{"feature1": 11.5, "feature2": 21.5},
		{"feature1": 12.5, "feature2": 22.5},
		{"feature1": 13.5, "feature2": 23.5},
	}
	
	// Test normal features
	normalFeatures := map[string]float64{"feature1": 11.0, "feature2": 21.0}
	result, err := detector.DetectIsolationAnomalies(context.Background(), normalFeatures, historicalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomalous)
	
	// Test anomalous features
	anomalousFeatures := map[string]float64{"feature1": 100.0, "feature2": 200.0}
	result, err = detector.DetectIsolationAnomalies(context.Background(), anomalousFeatures, historicalFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomalous)
	assert.Greater(t, result.AnomalyScore, detector.config.IsolationThreshold)
	assert.NotEmpty(t, result.AnomalyReasons)
}

func TestAnomalyDetector_ClusteringAnomalies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Create clustered historical data
	historicalFeatures := []map[string]float64{
		{"x": 1.0, "y": 1.0},
		{"x": 1.1, "y": 1.1},
		{"x": 0.9, "y": 0.9},
		{"x": 1.2, "y": 1.2},
		{"x": 0.8, "y": 0.8},
		{"x": 1.05, "y": 1.05},
		{"x": 0.95, "y": 0.95},
		{"x": 1.15, "y": 1.15},
		{"x": 0.85, "y": 0.85},
		{"x": 1.25, "y": 1.25},
	}
	
	// Test point close to cluster
	closeFeatures := map[string]float64{"x": 1.0, "y": 1.0}
	result, err := detector.DetectClusteringAnomalies(context.Background(), closeFeatures, historicalFeatures)
	require.NoError(t, err)
	assert.False(t, result.IsAnomalous)
	
	// Test point far from cluster
	farFeatures := map[string]float64{"x": 10.0, "y": 10.0}
	result, err = detector.DetectClusteringAnomalies(context.Background(), farFeatures, historicalFeatures)
	require.NoError(t, err)
	assert.True(t, result.IsAnomalous)
	assert.Greater(t, result.AnomalyScore, detector.config.ClusteringThreshold)
}

func TestAnomalyDetector_EnsembleAnomalies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Create test data
	features := map[string]float64{"feature1": 100.0, "feature2": 200.0}
	
	historicalFeatures := []map[string]float64{
		{"feature1": 10.0, "feature2": 20.0},
		{"feature1": 12.0, "feature2": 22.0},
		{"feature1": 11.0, "feature2": 21.0},
		{"feature1": 13.0, "feature2": 23.0},
		{"feature1": 9.0, "feature2": 19.0},
		{"feature1": 14.0, "feature2": 24.0},
		{"feature1": 10.5, "feature2": 20.5},
		{"feature1": 11.5, "feature2": 21.5},
		{"feature1": 12.5, "feature2": 22.5},
		{"feature1": 13.5, "feature2": 23.5},
	}
	
	historicalValues := map[string]*HistoricalData{
		"feature1": detector.BuildHistoricalData(
			[]float64{10, 12, 11, 13, 9, 14, 10.5, 11.5, 12.5, 13.5},
			make([]time.Time, 10),
		),
		"feature2": detector.BuildHistoricalData(
			[]float64{20, 22, 21, 23, 19, 24, 20.5, 21.5, 22.5, 23.5},
			make([]time.Time, 10),
		),
	}
	
	result, err := detector.DetectEnsembleAnomalies(context.Background(), features, historicalFeatures, historicalValues)
	require.NoError(t, err)
	
	assert.True(t, result.IsAnomalous)
	assert.Equal(t, "ensemble", result.Method)
	assert.Greater(t, result.EnsembleScore, 0.0)
	assert.Greater(t, result.Confidence, 0.5)
	assert.NotEmpty(t, result.AnomalyReasons)
	assert.Contains(t, result.Metadata, "method_count")
	assert.Contains(t, result.Metadata, "anomaly_votes")
}

func TestAnomalyDetector_EnsembleDisabled(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	detector := NewAnomalyDetector(logger)
	
	// Disable ensemble
	config := detector.GetConfig()
	config.EnableEnsemble = false
	detector.SetConfig(config)
	
	features := map[string]float64{"feature1": 100.0}
	historicalFeatures := []map[string]float64{{"feature1": 10.0}}
	historicalValues := map[string]*HistoricalData{}
	
	result, err := detector.DetectEnsembleAnomalies(context.Background(), features, historicalFeatures, historicalValues)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAnomalyDetector_BuildHistoricalData(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	timestamps := make([]time.Time, len(values))
	for i := range timestamps {
		timestamps[i] = time.Now().Add(-time.Duration(len(values)-i) * time.Hour)
	}
	
	historical := detector.BuildHistoricalData(values, timestamps)
	
	assert.Equal(t, values, historical.Values)
	assert.Equal(t, timestamps, historical.Timestamps)
	assert.Equal(t, 5.5, historical.Mean)
	assert.InDelta(t, 3.03, historical.StdDev, 0.01)
	assert.Equal(t, 1.0, historical.Min)
	assert.Equal(t, 10.0, historical.Max)
	
	// Check percentiles
	assert.Equal(t, 1.0, historical.Percentiles[5])   // 5th percentile
	assert.Equal(t, 3.0, historical.Percentiles[25])  // 25th percentile
	assert.Equal(t, 5.0, historical.Percentiles[50])  // 50th percentile (median)
	assert.Equal(t, 8.0, historical.Percentiles[75])  // 75th percentile
	assert.Equal(t, 10.0, historical.Percentiles[95]) // 95th percentile
}

func TestAnomalyDetector_EmptyHistoricalData(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	historical := detector.BuildHistoricalData([]float64{}, []time.Time{})
	
	assert.Empty(t, historical.Values)
	assert.Empty(t, historical.Timestamps)
	assert.Equal(t, 0.0, historical.Mean)
	assert.True(t, math.IsNaN(historical.StdDev))
	assert.NotNil(t, historical.Percentiles)
}

func TestAnomalyDetector_IQRScore(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	// Create data with known quartiles
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	historical := detector.BuildHistoricalData(values, make([]time.Time, len(values)))
	
	// Value within IQR should have score 0
	score := detector.calculateIQRScore(5.0, historical)
	assert.Equal(t, 0.0, score)
	
	// Value outside IQR should have positive score
	score = detector.calculateIQRScore(15.0, historical) // Far above Q3
	assert.Greater(t, score, 0.0)
	
	score = detector.calculateIQRScore(-5.0, historical) // Far below Q1
	assert.Greater(t, score, 0.0)
}

func TestAnomalyDetector_PercentileScore(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	historical := detector.BuildHistoricalData(values, make([]time.Time, len(values)))
	
	// Value in middle percentiles should have score 0
	score := detector.calculatePercentileScore(5.0, historical)
	assert.Equal(t, 0.0, score)
	
	// Value in extreme percentiles should have positive score
	score = detector.calculatePercentileScore(0.5, historical) // Below 5th percentile
	assert.Greater(t, score, 0.0)
	
	score = detector.calculatePercentileScore(10.5, historical) // Above 95th percentile
	assert.Greater(t, score, 0.0)
}

func TestAnomalyDetector_EuclideanDistance(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	features1 := map[string]float64{"x": 0, "y": 0}
	features2 := map[string]float64{"x": 3, "y": 4}
	
	distance := detector.calculateEuclideanDistance(features1, features2)
	assert.InDelta(t, 5.0, distance, 0.01) // 3-4-5 triangle
	
	// Test with no common features
	features3 := map[string]float64{"a": 1}
	features4 := map[string]float64{"b": 2}
	
	distance = detector.calculateEuclideanDistance(features3, features4)
	assert.True(t, math.IsInf(distance, 1))
}

func TestAnomalyDetector_KNNDistances(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	features := map[string]float64{"x": 0, "y": 0}
	historicalFeatures := []map[string]float64{
		{"x": 1, "y": 1},   // distance = sqrt(2) ≈ 1.41
		{"x": 2, "y": 2},   // distance = sqrt(8) ≈ 2.83
		{"x": 3, "y": 3},   // distance = sqrt(18) ≈ 4.24
		{"x": 0.5, "y": 0.5}, // distance = sqrt(0.5) ≈ 0.71
	}
	
	distances := detector.calculateKNNDistances(features, historicalFeatures, 3)
	
	assert.Len(t, distances, 3)
	assert.True(t, distances[0] <= distances[1])
	assert.True(t, distances[1] <= distances[2])
	assert.InDelta(t, 0.71, distances[0], 0.01) // Closest point
}

func TestAnomalyDetector_ConfidenceCalculation(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	// Low anomaly score should give low confidence
	confidence := detector.calculateConfidence(0.1)
	assert.Less(t, confidence, 0.5)
	
	// High anomaly score should give high confidence
	confidence = detector.calculateConfidence(0.9)
	assert.Greater(t, confidence, 0.5)
	
	// Score of 0.5 should give confidence around 0.5
	confidence = detector.calculateConfidence(0.5)
	assert.InDelta(t, 0.5, confidence, 0.1)
}

func TestAnomalyDetector_Configuration(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	// Test default configuration
	config := detector.GetConfig()
	assert.Equal(t, 0.7, config.StatisticalThreshold)
	assert.Equal(t, 0.6, config.IsolationThreshold)
	assert.True(t, config.EnableEnsemble)
	
	// Test updating configuration
	newConfig := &AnomalyDetectorConfig{
		StatisticalThreshold: 0.8,
		IsolationThreshold:   0.7,
		ClusteringThreshold:  0.75,
		EnsembleWeight:       0.65,
		WindowSize:           200,
		MinSamplesForStats:   20,
		EnableEnsemble:       false,
	}
	
	detector.SetConfig(newConfig)
	updatedConfig := detector.GetConfig()
	
	assert.Equal(t, 0.8, updatedConfig.StatisticalThreshold)
	assert.Equal(t, 0.7, updatedConfig.IsolationThreshold)
	assert.Equal(t, 0.75, updatedConfig.ClusteringThreshold)
	assert.Equal(t, 0.65, updatedConfig.EnsembleWeight)
	assert.Equal(t, 200, updatedConfig.WindowSize)
	assert.Equal(t, 20, updatedConfig.MinSamplesForStats)
	assert.False(t, updatedConfig.EnableEnsemble)
}

func TestAnomalyDetector_DeduplicateReasons(t *testing.T) {
	logger := logrus.New()
	detector := NewAnomalyDetector(logger)
	
	reasons := []string{
		"High Z-score: 3.50",
		"Outside IQR bounds",
		"High Z-score: 3.50", // Duplicate
		"Extreme percentile value",
		"Outside IQR bounds", // Duplicate
	}
	
	unique := detector.deduplicateReasons(reasons)
	
	assert.Len(t, unique, 3)
	assert.Contains(t, unique, "High Z-score: 3.50")
	assert.Contains(t, unique, "Outside IQR bounds")
	assert.Contains(t, unique, "Extreme percentile value")
}