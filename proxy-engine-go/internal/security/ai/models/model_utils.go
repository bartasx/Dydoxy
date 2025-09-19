package models

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
)

// ModelUtils provides utility functions for ML models
type ModelUtils struct{}

// NewModelUtils creates a new model utils instance
func NewModelUtils() *ModelUtils {
	return &ModelUtils{}
}

// NormalizeFeatures normalizes feature values to [0, 1] range using min-max normalization
func (mu *ModelUtils) NormalizeFeatures(features map[string]float64, minValues, maxValues map[string]float64) map[string]float64 {
	normalized := make(map[string]float64)
	
	for name, value := range features {
		minVal, hasMin := minValues[name]
		maxVal, hasMax := maxValues[name]
		
		if hasMin && hasMax && maxVal > minVal {
			// Min-max normalization: (value - min) / (max - min)
			normalized[name] = (value - minVal) / (maxVal - minVal)
		} else {
			// If no normalization parameters, keep original value
			normalized[name] = value
		}
	}
	
	return normalized
}

// StandardizeFeatures standardizes feature values using z-score normalization
func (mu *ModelUtils) StandardizeFeatures(features map[string]float64, means, stdDevs map[string]float64) map[string]float64 {
	standardized := make(map[string]float64)
	
	for name, value := range features {
		mean, hasMean := means[name]
		stdDev, hasStdDev := stdDevs[name]
		
		if hasMean && hasStdDev && stdDev > 0 {
			// Z-score normalization: (value - mean) / stdDev
			standardized[name] = (value - mean) / stdDev
		} else {
			// If no standardization parameters, keep original value
			standardized[name] = value
		}
	}
	
	return standardized
}

// CalculateConfidence calculates confidence score from model output
func (mu *ModelUtils) CalculateConfidence(probability float64) float64 {
	// Convert probability to confidence score
	// Higher confidence for probabilities closer to 0 or 1
	if probability >= 0.5 {
		return probability
	}
	return 1.0 - probability
}

// ApplyThreshold applies threshold to probability to get binary classification
func (mu *ModelUtils) ApplyThreshold(probability, threshold float64) bool {
	return probability >= threshold
}

// CalculateMetrics calculates classification metrics from predictions and labels
func (mu *ModelUtils) CalculateMetrics(predictions []bool, labels []bool, probabilities []float64) (*ai.ModelMetrics, error) {
	if len(predictions) != len(labels) {
		return nil, fmt.Errorf("predictions and labels must have same length")
	}
	
	if len(predictions) == 0 {
		return nil, fmt.Errorf("cannot calculate metrics for empty predictions")
	}
	
	var truePositives, falsePositives, trueNegatives, falseNegatives int64
	
	for i := 0; i < len(predictions); i++ {
		predicted := predictions[i]
		actual := labels[i]
		
		if predicted && actual {
			truePositives++
		} else if predicted && !actual {
			falsePositives++
		} else if !predicted && actual {
			falseNegatives++
		} else {
			trueNegatives++
		}
	}
	
	total := float64(len(predictions))
	accuracy := float64(truePositives+trueNegatives) / total
	
	var precision, recall, f1Score float64
	
	if truePositives+falsePositives > 0 {
		precision = float64(truePositives) / float64(truePositives+falsePositives)
	}
	
	if truePositives+falseNegatives > 0 {
		recall = float64(truePositives) / float64(truePositives+falseNegatives)
	}
	
	if precision+recall > 0 {
		f1Score = 2 * (precision * recall) / (precision + recall)
	}
	
	return &ai.ModelMetrics{
		Accuracy:       accuracy,
		Precision:      precision,
		Recall:         recall,
		F1Score:        f1Score,
		TruePositives:  truePositives,
		FalsePositives: falsePositives,
		TrueNegatives:  trueNegatives,
		FalseNegatives: falseNegatives,
		LastEvaluated:  time.Now(),
	}, nil
}

// ValidateTrainingData validates training examples for consistency
func (mu *ModelUtils) ValidateTrainingData(examples []*ai.TrainingExample) error {
	if len(examples) == 0 {
		return fmt.Errorf("training data cannot be empty")
	}
	
	// Check feature consistency
	var featureNames []string
	for name := range examples[0].Features {
		featureNames = append(featureNames, name)
	}
	
	for i, example := range examples {
		if len(example.Features) != len(featureNames) {
			return fmt.Errorf("example %d has different number of features", i)
		}
		
		for _, name := range featureNames {
			if _, exists := example.Features[name]; !exists {
				return fmt.Errorf("example %d missing feature %s", i, name)
			}
			
			// Check for invalid values
			value := example.Features[name]
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("example %d has invalid value for feature %s", i, name)
			}
		}
	}
	
	return nil
}

// SplitTrainingData splits training data into train and validation sets
func (mu *ModelUtils) SplitTrainingData(examples []*ai.TrainingExample, trainRatio float64) ([]*ai.TrainingExample, []*ai.TrainingExample, error) {
	if trainRatio <= 0 || trainRatio >= 1 {
		return nil, nil, fmt.Errorf("train ratio must be between 0 and 1")
	}
	
	if len(examples) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 examples to split")
	}
	
	trainSize := int(float64(len(examples)) * trainRatio)
	if trainSize == 0 {
		trainSize = 1
	}
	if trainSize == len(examples) {
		trainSize = len(examples) - 1
	}
	
	trainData := make([]*ai.TrainingExample, trainSize)
	validationData := make([]*ai.TrainingExample, len(examples)-trainSize)
	
	copy(trainData, examples[:trainSize])
	copy(validationData, examples[trainSize:])
	
	return trainData, validationData, nil
}

// BalanceTrainingData balances training data by ensuring equal representation of classes
func (mu *ModelUtils) BalanceTrainingData(examples []*ai.TrainingExample) []*ai.TrainingExample {
	var positiveExamples, negativeExamples []*ai.TrainingExample
	
	for _, example := range examples {
		if example.Label {
			positiveExamples = append(positiveExamples, example)
		} else {
			negativeExamples = append(negativeExamples, example)
		}
	}
	
	// Use the smaller class size as the target
	targetSize := len(positiveExamples)
	if len(negativeExamples) < targetSize {
		targetSize = len(negativeExamples)
	}
	
	if targetSize == 0 {
		return examples // Cannot balance if one class is empty
	}
	
	balanced := make([]*ai.TrainingExample, 0, targetSize*2)
	
	// Add positive examples
	for i := 0; i < targetSize && i < len(positiveExamples); i++ {
		balanced = append(balanced, positiveExamples[i])
	}
	
	// Add negative examples
	for i := 0; i < targetSize && i < len(negativeExamples); i++ {
		balanced = append(balanced, negativeExamples[i])
	}
	
	return balanced
}

// CreatePrediction creates an ML prediction result
func (mu *ModelUtils) CreatePrediction(modelName, modelVersion string, isThreat bool, confidence float64, threatType ai.ThreatType, features map[string]float64) *ai.MLPrediction {
	return &ai.MLPrediction{
		ModelName:    modelName,
		ModelVersion: modelVersion,
		IsThreat:     isThreat,
		Confidence:   confidence,
		ThreatType:   threatType,
		Features:     features,
		Metadata:     make(map[string]interface{}),
		Timestamp:    time.Now(),
	}
}

// EvaluateModel evaluates a model against test data
func (mu *ModelUtils) EvaluateModel(ctx context.Context, model ai.MLModel, testData []*ai.TrainingExample) (*ai.ModelMetrics, error) {
	if len(testData) == 0 {
		return nil, fmt.Errorf("test data cannot be empty")
	}
	
	predictions := make([]bool, len(testData))
	labels := make([]bool, len(testData))
	probabilities := make([]float64, len(testData))
	
	for i, example := range testData {
		prediction, err := model.Predict(ctx, example.Features)
		if err != nil {
			return nil, fmt.Errorf("prediction failed for example %d: %w", i, err)
		}
		
		predictions[i] = prediction.IsThreat
		labels[i] = example.Label
		probabilities[i] = prediction.Confidence
	}
	
	return mu.CalculateMetrics(predictions, labels, probabilities)
}

// GetFeatureImportance calculates feature importance based on variance
func (mu *ModelUtils) GetFeatureImportance(examples []*ai.TrainingExample) (map[string]float64, error) {
	if len(examples) == 0 {
		return nil, fmt.Errorf("cannot calculate feature importance for empty data")
	}
	
	// Get feature names
	var featureNames []string
	for name := range examples[0].Features {
		featureNames = append(featureNames, name)
	}
	
	importance := make(map[string]float64)
	
	for _, featureName := range featureNames {
		// Calculate variance for this feature
		var sum, sumSquares float64
		count := float64(len(examples))
		
		for _, example := range examples {
			value := example.Features[featureName]
			sum += value
			sumSquares += value * value
		}
		
		mean := sum / count
		variance := (sumSquares / count) - (mean * mean)
		
		// Use variance as a simple measure of importance
		importance[featureName] = variance
	}
	
	return importance, nil
}

// CrossValidate performs k-fold cross validation
func (mu *ModelUtils) CrossValidate(ctx context.Context, model ai.MLModel, examples []*ai.TrainingExample, k int) (*ai.ModelMetrics, error) {
	if k <= 1 {
		return nil, fmt.Errorf("k must be greater than 1")
	}
	
	if len(examples) < k {
		return nil, fmt.Errorf("not enough examples for %d-fold cross validation", k)
	}
	
	foldSize := len(examples) / k
	var allPredictions, allLabels []bool
	var allProbabilities []float64
	
	for fold := 0; fold < k; fold++ {
		// Create train and test sets for this fold
		testStart := fold * foldSize
		testEnd := testStart + foldSize
		if fold == k-1 {
			testEnd = len(examples) // Include remaining examples in last fold
		}
		
		testData := examples[testStart:testEnd]
		trainData := append(examples[:testStart], examples[testEnd:]...)
		
		// Train model on training data
		if err := model.Train(ctx, trainData); err != nil {
			return nil, fmt.Errorf("training failed for fold %d: %w", fold, err)
		}
		
		// Evaluate on test data
		for _, example := range testData {
			prediction, err := model.Predict(ctx, example.Features)
			if err != nil {
				return nil, fmt.Errorf("prediction failed in fold %d: %w", fold, err)
			}
			
			allPredictions = append(allPredictions, prediction.IsThreat)
			allLabels = append(allLabels, example.Label)
			allProbabilities = append(allProbabilities, prediction.Confidence)
		}
	}
	
	return mu.CalculateMetrics(allPredictions, allLabels, allProbabilities)
}