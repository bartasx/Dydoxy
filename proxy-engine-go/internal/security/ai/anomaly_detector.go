package ai

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
)

// AnomalyDetector provides advanced anomaly detection algorithms
type AnomalyDetector struct {
	logger *logrus.Logger
	config *AnomalyDetectorConfig
}

// AnomalyDetectorConfig holds configuration for anomaly detection
type AnomalyDetectorConfig struct {
	StatisticalThreshold  float64 `json:"statistical_threshold"`  // Z-score threshold
	IsolationThreshold    float64 `json:"isolation_threshold"`    // Isolation forest threshold
	ClusteringThreshold   float64 `json:"clustering_threshold"`   // Clustering-based threshold
	EnsembleWeight        float64 `json:"ensemble_weight"`        // Weight for ensemble methods
	WindowSize            int     `json:"window_size"`            // Sliding window size
	MinSamplesForStats    int     `json:"min_samples_for_stats"`  // Minimum samples for statistics
	EnableEnsemble        bool    `json:"enable_ensemble"`        // Enable ensemble methods
}

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	IsAnomalous       bool                   `json:"is_anomalous"`
	AnomalyScore      float64                `json:"anomaly_score"`
	StatisticalScore  float64                `json:"statistical_score"`
	IsolationScore    float64                `json:"isolation_score"`
	ClusteringScore   float64                `json:"clustering_score"`
	EnsembleScore     float64                `json:"ensemble_score"`
	Method            string                 `json:"method"`
	Confidence        float64                `json:"confidence"`
	AnomalyReasons    []string               `json:"anomaly_reasons"`
	FeatureScores     map[string]float64     `json:"feature_scores"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timestamp         time.Time              `json:"timestamp"`
}

// HistoricalData represents historical data for anomaly detection
type HistoricalData struct {
	Values     []float64 `json:"values"`
	Timestamps []time.Time `json:"timestamps"`
	Mean       float64   `json:"mean"`
	StdDev     float64   `json:"std_dev"`
	Min        float64   `json:"min"`
	Max        float64   `json:"max"`
	Percentiles map[int]float64 `json:"percentiles"`
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(logger *logrus.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		logger: logger,
		config: getDefaultAnomalyDetectorConfig(),
	}
}

// DetectStatisticalAnomalies detects anomalies using statistical methods (Z-score, IQR)
func (ad *AnomalyDetector) DetectStatisticalAnomalies(ctx context.Context, value float64, historical *HistoricalData) (*AnomalyResult, error) {
	if len(historical.Values) < ad.config.MinSamplesForStats {
		return &AnomalyResult{
			IsAnomalous:  false,
			AnomalyScore: 0.0,
			Method:       "statistical",
			Confidence:   0.0,
			Timestamp:    time.Now(),
		}, nil
	}
	
	// Calculate Z-score
	zScore := 0.0
	if historical.StdDev > 0 {
		zScore = math.Abs(value-historical.Mean) / historical.StdDev
	}
	
	// Calculate IQR-based score
	iqrScore := ad.calculateIQRScore(value, historical)
	
	// Calculate percentile-based score
	percentileScore := ad.calculatePercentileScore(value, historical)
	
	// Combine scores
	statisticalScore := math.Max(zScore/3.0, math.Max(iqrScore, percentileScore))
	
	isAnomalous := statisticalScore >= ad.config.StatisticalThreshold
	
	var reasons []string
	if zScore >= 3.0 {
		reasons = append(reasons, fmt.Sprintf("High Z-score: %.2f", zScore))
	}
	if iqrScore >= 0.8 {
		reasons = append(reasons, "Outside IQR bounds")
	}
	if percentileScore >= 0.9 {
		reasons = append(reasons, "Extreme percentile value")
	}
	
	return &AnomalyResult{
		IsAnomalous:      isAnomalous,
		AnomalyScore:     statisticalScore,
		StatisticalScore: statisticalScore,
		Method:           "statistical",
		Confidence:       ad.calculateConfidence(statisticalScore),
		AnomalyReasons:   reasons,
		FeatureScores: map[string]float64{
			"z_score":         zScore,
			"iqr_score":       iqrScore,
			"percentile_score": percentileScore,
		},
		Timestamp: time.Now(),
	}, nil
}

// DetectIsolationAnomalies detects anomalies using isolation forest-like algorithm
func (ad *AnomalyDetector) DetectIsolationAnomalies(ctx context.Context, features map[string]float64, historicalFeatures []map[string]float64) (*AnomalyResult, error) {
	if len(historicalFeatures) < ad.config.MinSamplesForStats {
		return &AnomalyResult{
			IsAnomalous:  false,
			AnomalyScore: 0.0,
			Method:       "isolation",
			Confidence:   0.0,
			Timestamp:    time.Now(),
		}, nil
	}
	
	// Calculate isolation score for each feature
	featureScores := make(map[string]float64)
	var totalScore float64
	
	for featureName, featureValue := range features {
		// Extract historical values for this feature
		var historicalValues []float64
		for _, historical := range historicalFeatures {
			if val, exists := historical[featureName]; exists {
				historicalValues = append(historicalValues, val)
			}
		}
		
		if len(historicalValues) == 0 {
			continue
		}
		
		// Calculate isolation score (simplified version)
		isolationScore := ad.calculateIsolationScore(featureValue, historicalValues)
		featureScores[featureName] = isolationScore
		totalScore += isolationScore
	}
	
	// Average isolation score
	avgIsolationScore := 0.0
	if len(featureScores) > 0 {
		avgIsolationScore = totalScore / float64(len(featureScores))
	}
	
	isAnomalous := avgIsolationScore >= ad.config.IsolationThreshold
	
	var reasons []string
	for featureName, score := range featureScores {
		if score >= ad.config.IsolationThreshold {
			reasons = append(reasons, fmt.Sprintf("Feature %s isolated: %.2f", featureName, score))
		}
	}
	
	return &AnomalyResult{
		IsAnomalous:     isAnomalous,
		AnomalyScore:    avgIsolationScore,
		IsolationScore:  avgIsolationScore,
		Method:          "isolation",
		Confidence:      ad.calculateConfidence(avgIsolationScore),
		AnomalyReasons:  reasons,
		FeatureScores:   featureScores,
		Timestamp:       time.Now(),
	}, nil
}

// DetectClusteringAnomalies detects anomalies using clustering-based methods
func (ad *AnomalyDetector) DetectClusteringAnomalies(ctx context.Context, features map[string]float64, historicalFeatures []map[string]float64) (*AnomalyResult, error) {
	if len(historicalFeatures) < ad.config.MinSamplesForStats {
		return &AnomalyResult{
			IsAnomalous:  false,
			AnomalyScore: 0.0,
			Method:       "clustering",
			Confidence:   0.0,
			Timestamp:    time.Now(),
		}, nil
	}
	
	// Calculate distance to nearest neighbors (simplified k-NN approach)
	distances := ad.calculateKNNDistances(features, historicalFeatures, 5)
	
	// Calculate clustering score based on average distance to k nearest neighbors
	avgDistance := 0.0
	for _, distance := range distances {
		avgDistance += distance
	}
	avgDistance /= float64(len(distances))
	
	// Normalize distance to [0, 1] range
	clusteringScore := math.Min(1.0, avgDistance/10.0) // Assuming max reasonable distance is 10
	
	isAnomalous := clusteringScore >= ad.config.ClusteringThreshold
	
	var reasons []string
	if clusteringScore >= ad.config.ClusteringThreshold {
		reasons = append(reasons, fmt.Sprintf("High distance to neighbors: %.2f", avgDistance))
	}
	
	return &AnomalyResult{
		IsAnomalous:     isAnomalous,
		AnomalyScore:    clusteringScore,
		ClusteringScore: clusteringScore,
		Method:          "clustering",
		Confidence:      ad.calculateConfidence(clusteringScore),
		AnomalyReasons:  reasons,
		FeatureScores: map[string]float64{
			"avg_distance": avgDistance,
			"min_distance": distances[0],
			"max_distance": distances[len(distances)-1],
		},
		Timestamp: time.Now(),
	}, nil
}

// DetectEnsembleAnomalies combines multiple anomaly detection methods
func (ad *AnomalyDetector) DetectEnsembleAnomalies(ctx context.Context, features map[string]float64, historicalFeatures []map[string]float64, historicalValues map[string]*HistoricalData) (*AnomalyResult, error) {
	if !ad.config.EnableEnsemble {
		return nil, fmt.Errorf("ensemble methods are disabled")
	}
	
	var results []*AnomalyResult
	var weights []float64
	
	// Run isolation forest detection
	isolationResult, err := ad.DetectIsolationAnomalies(ctx, features, historicalFeatures)
	if err == nil {
		results = append(results, isolationResult)
		weights = append(weights, 0.4) // 40% weight
	}
	
	// Run clustering detection
	clusteringResult, err := ad.DetectClusteringAnomalies(ctx, features, historicalFeatures)
	if err == nil {
		results = append(results, clusteringResult)
		weights = append(weights, 0.3) // 30% weight
	}
	
	// Run statistical detection for key features
	statisticalWeight := 0.3 / float64(len(historicalValues))
	for featureName, historical := range historicalValues {
		if featureValue, exists := features[featureName]; exists {
			statResult, err := ad.DetectStatisticalAnomalies(ctx, featureValue, historical)
			if err == nil {
				results = append(results, statResult)
				weights = append(weights, statisticalWeight)
			}
		}
	}
	
	if len(results) == 0 {
		return &AnomalyResult{
			IsAnomalous:  false,
			AnomalyScore: 0.0,
			Method:       "ensemble",
			Confidence:   0.0,
			Timestamp:    time.Now(),
		}, nil
	}
	
	// Calculate weighted ensemble score
	var weightedScore float64
	var totalWeight float64
	var allReasons []string
	combinedFeatureScores := make(map[string]float64)
	
	for i, result := range results {
		weight := weights[i]
		weightedScore += result.AnomalyScore * weight
		totalWeight += weight
		allReasons = append(allReasons, result.AnomalyReasons...)
		
		// Combine feature scores
		for feature, score := range result.FeatureScores {
			combinedFeatureScores[fmt.Sprintf("%s_%s", result.Method, feature)] = score
		}
	}
	
	ensembleScore := weightedScore / totalWeight
	isAnomalous := ensembleScore >= ad.config.EnsembleWeight
	
	// Count votes for anomaly
	anomalyVotes := 0
	for _, result := range results {
		if result.IsAnomalous {
			anomalyVotes++
		}
	}
	
	// Override ensemble decision if majority vote differs significantly
	majorityAnomalous := float64(anomalyVotes) > float64(len(results))/2
	if majorityAnomalous != isAnomalous && math.Abs(ensembleScore-ad.config.EnsembleWeight) < 0.1 {
		isAnomalous = majorityAnomalous
	}
	
	return &AnomalyResult{
		IsAnomalous:      isAnomalous,
		AnomalyScore:     ensembleScore,
		StatisticalScore: ad.getMethodScore(results, "statistical"),
		IsolationScore:   ad.getMethodScore(results, "isolation"),
		ClusteringScore:  ad.getMethodScore(results, "clustering"),
		EnsembleScore:    ensembleScore,
		Method:           "ensemble",
		Confidence:       ad.calculateConfidence(ensembleScore),
		AnomalyReasons:   ad.deduplicateReasons(allReasons),
		FeatureScores:    combinedFeatureScores,
		Metadata: map[string]interface{}{
			"method_count":   len(results),
			"anomaly_votes":  anomalyVotes,
			"total_weight":   totalWeight,
		},
		Timestamp: time.Now(),
	}, nil
}

// Helper methods

// calculateIQRScore calculates anomaly score based on Interquartile Range
func (ad *AnomalyDetector) calculateIQRScore(value float64, historical *HistoricalData) float64 {
	q25, exists25 := historical.Percentiles[25]
	q75, exists75 := historical.Percentiles[75]
	
	if !exists25 || !exists75 {
		return 0.0
	}
	
	iqr := q75 - q25
	if iqr == 0 {
		return 0.0
	}
	
	// Calculate how far outside the IQR bounds the value is
	lowerBound := q25 - 1.5*iqr
	upperBound := q75 + 1.5*iqr
	
	if value < lowerBound {
		return math.Min(1.0, (lowerBound-value)/iqr)
	} else if value > upperBound {
		return math.Min(1.0, (value-upperBound)/iqr)
	}
	
	return 0.0
}

// calculatePercentileScore calculates anomaly score based on percentile position
func (ad *AnomalyDetector) calculatePercentileScore(value float64, historical *HistoricalData) float64 {
	// Count how many historical values are less than current value
	count := 0
	for _, v := range historical.Values {
		if v < value {
			count++
		}
	}
	
	percentile := float64(count) / float64(len(historical.Values))
	
	// Values in extreme percentiles (< 5% or > 95%) are anomalous
	if percentile < 0.05 {
		return (0.05 - percentile) * 20 // Scale to [0, 1]
	} else if percentile > 0.95 {
		return (percentile - 0.95) * 20 // Scale to [0, 1]
	}
	
	return 0.0
}

// calculateIsolationScore calculates isolation score for a value
func (ad *AnomalyDetector) calculateIsolationScore(value float64, historicalValues []float64) float64 {
	if len(historicalValues) == 0 {
		return 0.0
	}
	
	// Simple isolation score: how far the value is from the median
	sort.Float64s(historicalValues)
	median := historicalValues[len(historicalValues)/2]
	
	// Calculate MAD (Median Absolute Deviation)
	var deviations []float64
	for _, v := range historicalValues {
		deviations = append(deviations, math.Abs(v-median))
	}
	sort.Float64s(deviations)
	mad := deviations[len(deviations)/2]
	
	if mad == 0 {
		mad = 1.0 // Avoid division by zero
	}
	
	// Modified Z-score using MAD
	modifiedZScore := 0.6745 * math.Abs(value-median) / mad
	
	// Convert to [0, 1] range
	return math.Min(1.0, modifiedZScore/3.5)
}

// calculateKNNDistances calculates distances to k nearest neighbors
func (ad *AnomalyDetector) calculateKNNDistances(features map[string]float64, historicalFeatures []map[string]float64, k int) []float64 {
	var distances []float64
	
	for _, historical := range historicalFeatures {
		distance := ad.calculateEuclideanDistance(features, historical)
		distances = append(distances, distance)
	}
	
	// Sort distances and return k smallest
	sort.Float64s(distances)
	
	kValue := k
	if len(distances) < k {
		kValue = len(distances)
	}
	
	return distances[:kValue]
}

// calculateEuclideanDistance calculates Euclidean distance between two feature vectors
func (ad *AnomalyDetector) calculateEuclideanDistance(features1, features2 map[string]float64) float64 {
	var sumSquares float64
	var count int
	
	for feature, value1 := range features1 {
		if value2, exists := features2[feature]; exists {
			diff := value1 - value2
			sumSquares += diff * diff
			count++
		}
	}
	
	if count == 0 {
		return math.Inf(1)
	}
	
	return math.Sqrt(sumSquares / float64(count))
}

// calculateConfidence calculates confidence score based on anomaly score
func (ad *AnomalyDetector) calculateConfidence(anomalyScore float64) float64 {
	// Sigmoid function to convert anomaly score to confidence
	return 1.0 / (1.0 + math.Exp(-5*(anomalyScore-0.5)))
}

// getMethodScore extracts score for a specific method from results
func (ad *AnomalyDetector) getMethodScore(results []*AnomalyResult, method string) float64 {
	for _, result := range results {
		if result.Method == method {
			return result.AnomalyScore
		}
	}
	return 0.0
}

// deduplicateReasons removes duplicate reasons from the list
func (ad *AnomalyDetector) deduplicateReasons(reasons []string) []string {
	seen := make(map[string]bool)
	var unique []string
	
	for _, reason := range reasons {
		if !seen[reason] {
			seen[reason] = true
			unique = append(unique, reason)
		}
	}
	
	return unique
}

// BuildHistoricalData builds historical data structure from values
func (ad *AnomalyDetector) BuildHistoricalData(values []float64, timestamps []time.Time) *HistoricalData {
	if len(values) == 0 {
		return &HistoricalData{
			Values:      []float64{},
			Timestamps:  []time.Time{},
			Percentiles: make(map[int]float64),
		}
	}
	
	// Calculate basic statistics
	var sum float64
	min := values[0]
	max := values[0]
	
	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	
	mean := sum / float64(len(values))
	
	// Calculate standard deviation
	var sumSquares float64
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	stdDev := math.Sqrt(sumSquares / float64(len(values)))
	
	// Calculate percentiles
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)
	sort.Float64s(sortedValues)
	
	percentiles := make(map[int]float64)
	percentilePoints := []int{5, 10, 25, 50, 75, 90, 95}
	
	for _, p := range percentilePoints {
		index := int(float64(p) / 100.0 * float64(len(sortedValues)-1))
		if index >= len(sortedValues) {
			index = len(sortedValues) - 1
		}
		percentiles[p] = sortedValues[index]
	}
	
	return &HistoricalData{
		Values:      values,
		Timestamps:  timestamps,
		Mean:        mean,
		StdDev:      stdDev,
		Min:         min,
		Max:         max,
		Percentiles: percentiles,
	}
}

// SetConfig updates the anomaly detector configuration
func (ad *AnomalyDetector) SetConfig(config *AnomalyDetectorConfig) {
	ad.config = config
	ad.logger.Info("Updated anomaly detector configuration")
}

// GetConfig returns the current configuration
func (ad *AnomalyDetector) GetConfig() *AnomalyDetectorConfig {
	return ad.config
}

// getDefaultAnomalyDetectorConfig returns default configuration
func getDefaultAnomalyDetectorConfig() *AnomalyDetectorConfig {
	return &AnomalyDetectorConfig{
		StatisticalThreshold: 0.7,
		IsolationThreshold:   0.6,
		ClusteringThreshold:  0.65,
		EnsembleWeight:       0.6,
		WindowSize:           100,
		MinSamplesForStats:   10,
		EnableEnsemble:       true,
	}
}