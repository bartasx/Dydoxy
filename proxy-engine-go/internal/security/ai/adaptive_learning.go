package ai

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AdaptiveLearningSystem manages continuous learning and model improvement
type AdaptiveLearningSystem struct {
	storage           AIStorage
	threatDetector    AIThreatDetector
	modelManager      ModelManager
	feedbackBuffer    []*FeedbackExample
	config            *AdaptiveLearningConfig
	stats             *LearningStats
	logger            *logrus.Logger
	mu                sync.RWMutex
}

// AdaptiveLearningConfig holds configuration for adaptive learning
type AdaptiveLearningConfig struct {
	EnabledLearning        bool          `json:"enabled_learning"`
	FeedbackBufferSize     int           `json:"feedback_buffer_size"`
	MinFeedbackForUpdate   int           `json:"min_feedback_for_update"`
	LearningRate           float64       `json:"learning_rate"`
	RetrainingInterval     time.Duration `json:"retraining_interval"`
	PerformanceThreshold   float64       `json:"performance_threshold"`
	MaxTrainingExamples    int           `json:"max_training_examples"`
	EnableAutoRetraining   bool          `json:"enable_auto_retraining"`
	EnableFeedbackLearning bool          `json:"enable_feedback_learning"`
	ValidationSplit        float64       `json:"validation_split"`
}

// FeedbackExample represents user feedback on threat detection
type FeedbackExample struct {
	ID               string                 `json:"id"`
	RequestID        string                 `json:"request_id"`
	OriginalResult   *ThreatAnalysisResult  `json:"original_result"`
	UserFeedback     FeedbackType           `json:"user_feedback"`
	CorrectLabel     bool                   `json:"correct_label"`
	CorrectThreatType ThreatType            `json:"correct_threat_type,omitempty"`
	Features         map[string]float64     `json:"features"`
	Confidence       float64                `json:"confidence"`
	Source           string                 `json:"source"`
	Timestamp        time.Time              `json:"timestamp"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// FeedbackType defines types of user feedback
type FeedbackType string

const (
	FeedbackTruePositive  FeedbackType = "true_positive"  // Correctly identified threat
	FeedbackFalsePositive FeedbackType = "false_positive" // Incorrectly identified as threat
	FeedbackTrueNegative  FeedbackType = "true_negative"  // Correctly identified as safe
	FeedbackFalseNegative FeedbackType = "false_negative" // Missed threat
	FeedbackReclassify    FeedbackType = "reclassify"     // Correct threat but wrong type
)

// LearningStats tracks adaptive learning statistics
type LearningStats struct {
	TotalFeedback        int64                    `json:"total_feedback"`
	FeedbackByType       map[FeedbackType]int64   `json:"feedback_by_type"`
	ModelUpdates         int64                    `json:"model_updates"`
	LastRetraining       time.Time                `json:"last_retraining"`
	PerformanceHistory   []PerformanceSnapshot    `json:"performance_history"`
	FeedbackAccuracy     float64                  `json:"feedback_accuracy"`
	LearningEffectiveness float64                 `json:"learning_effectiveness"`
	LastUpdated          time.Time                `json:"last_updated"`
}

// PerformanceSnapshot captures model performance at a point in time
type PerformanceSnapshot struct {
	Timestamp        time.Time     `json:"timestamp"`
	Accuracy         float64       `json:"accuracy"`
	Precision        float64       `json:"precision"`
	Recall           float64       `json:"recall"`
	F1Score          float64       `json:"f1_score"`
	FalsePositiveRate float64      `json:"false_positive_rate"`
	ModelVersion     string        `json:"model_version"`
	TrainingSize     int           `json:"training_size"`
	ValidationSize   int           `json:"validation_size"`
}

// NewAdaptiveLearningSystem creates a new adaptive learning system
func NewAdaptiveLearningSystem(storage AIStorage, threatDetector AIThreatDetector, modelManager ModelManager, logger *logrus.Logger) *AdaptiveLearningSystem {
	return &AdaptiveLearningSystem{
		storage:        storage,
		threatDetector: threatDetector,
		modelManager:   modelManager,
		feedbackBuffer: make([]*FeedbackExample, 0),
		config:         getDefaultAdaptiveLearningConfig(),
		stats:          getDefaultLearningStats(),
		logger:         logger,
	}
}

// ProcessFeedback processes user feedback and updates the learning system
func (als *AdaptiveLearningSystem) ProcessFeedback(ctx context.Context, feedback *FeedbackExample) error {
	if !als.config.EnabledLearning || !als.config.EnableFeedbackLearning {
		return fmt.Errorf("feedback learning is disabled")
	}
	
	als.mu.Lock()
	defer als.mu.Unlock()
	
	// Add to feedback buffer
	als.feedbackBuffer = append(als.feedbackBuffer, feedback)
	
	// Maintain buffer size
	if len(als.feedbackBuffer) > als.config.FeedbackBufferSize {
		als.feedbackBuffer = als.feedbackBuffer[1:]
	}
	
	// Update statistics
	als.stats.TotalFeedback++
	als.stats.FeedbackByType[feedback.UserFeedback]++
	als.stats.LastUpdated = time.Now()
	
	// Save feedback to storage
	trainingExample := als.convertFeedbackToTrainingExample(feedback)
	if err := als.storage.SaveTrainingExample(ctx, trainingExample); err != nil {
		als.logger.Warnf("Failed to save training example: %v", err)
	}
	
	als.logger.WithFields(logrus.Fields{
		"feedback_type": feedback.UserFeedback,
		"request_id":    feedback.RequestID,
		"buffer_size":   len(als.feedbackBuffer),
	}).Debug("Processed feedback")
	
	// Check if we should trigger learning
	if len(als.feedbackBuffer) >= als.config.MinFeedbackForUpdate {
		go als.triggerIncrementalLearning(ctx)
	}
	
	return nil
}

// triggerIncrementalLearning performs incremental learning based on feedback
func (als *AdaptiveLearningSystem) triggerIncrementalLearning(ctx context.Context) {
	als.logger.Info("Triggering incremental learning from feedback")
	
	als.mu.RLock()
	feedbackCopy := make([]*FeedbackExample, len(als.feedbackBuffer))
	copy(feedbackCopy, als.feedbackBuffer)
	als.mu.RUnlock()
	
	// Convert feedback to training examples
	var trainingExamples []*TrainingExample
	for _, feedback := range feedbackCopy {
		example := als.convertFeedbackToTrainingExample(feedback)
		trainingExamples = append(trainingExamples, example)
	}
	
	// Update models with new training data
	if err := als.threatDetector.UpdateModels(ctx, trainingExamples); err != nil {
		als.logger.Errorf("Failed to update models with feedback: %v", err)
		return
	}
	
	als.mu.Lock()
	als.stats.ModelUpdates++
	als.mu.Unlock()
	
	// Evaluate performance after update
	als.evaluatePerformance(ctx, trainingExamples)
	
	als.logger.Infof("Incremental learning completed with %d feedback examples", len(trainingExamples))
}

// ScheduleRetraining schedules periodic model retraining
func (als *AdaptiveLearningSystem) ScheduleRetraining(ctx context.Context) {
	if !als.config.EnabledLearning || !als.config.EnableAutoRetraining {
		return
	}
	
	ticker := time.NewTicker(als.config.RetrainingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			als.performFullRetraining(ctx)
		}
	}
}

// performFullRetraining performs comprehensive model retraining
func (als *AdaptiveLearningSystem) performFullRetraining(ctx context.Context) {
	als.logger.Info("Starting full model retraining")
	
	// Load training examples from storage
	trainingExamples, err := als.storage.LoadTrainingExamples(ctx, als.config.MaxTrainingExamples, 0)
	if err != nil {
		als.logger.Errorf("Failed to load training examples: %v", err)
		return
	}
	
	if len(trainingExamples) < als.config.MinFeedbackForUpdate {
		als.logger.Infof("Insufficient training data for retraining: %d examples", len(trainingExamples))
		return
	}
	
	// Balance training data
	balancedExamples := als.balanceTrainingData(trainingExamples)
	
	// Split into training and validation sets
	trainData, validationData := als.splitTrainingData(balancedExamples)
	
	// Perform retraining
	if err := als.threatDetector.UpdateModels(ctx, trainData); err != nil {
		als.logger.Errorf("Failed to retrain models: %v", err)
		return
	}
	
	// Evaluate performance
	performance := als.evaluateModelPerformance(ctx, validationData)
	
	// Update statistics
	als.mu.Lock()
	als.stats.ModelUpdates++
	als.stats.LastRetraining = time.Now()
	als.stats.PerformanceHistory = append(als.stats.PerformanceHistory, *performance)
	
	// Keep only last 100 performance snapshots
	if len(als.stats.PerformanceHistory) > 100 {
		als.stats.PerformanceHistory = als.stats.PerformanceHistory[1:]
	}
	als.mu.Unlock()
	
	// Check if performance meets threshold
	if performance.Accuracy < als.config.PerformanceThreshold {
		als.logger.Warnf("Model performance below threshold: %.3f < %.3f", 
			performance.Accuracy, als.config.PerformanceThreshold)
		als.handlePoorPerformance(ctx, performance)
	}
	
	als.logger.Infof("Full retraining completed - Accuracy: %.3f, F1: %.3f", 
		performance.Accuracy, performance.F1Score)
}

// evaluatePerformance evaluates model performance after updates
func (als *AdaptiveLearningSystem) evaluatePerformance(ctx context.Context, examples []*TrainingExample) {
	if len(examples) == 0 {
		return
	}
	
	// Simple performance evaluation based on feedback accuracy
	correctFeedback := 0
	for _, example := range examples {
		// Check if the feedback aligns with the model's prediction
		// This is a simplified evaluation - in practice, you'd use a validation set
		if (example.Label && example.Source == string(FeedbackTruePositive)) ||
		   (!example.Label && example.Source == string(FeedbackTrueNegative)) {
			correctFeedback++
		}
	}
	
	accuracy := float64(correctFeedback) / float64(len(examples))
	
	als.mu.Lock()
	als.stats.FeedbackAccuracy = accuracy
	als.stats.LearningEffectiveness = als.calculateLearningEffectiveness()
	als.mu.Unlock()
	
	als.logger.Infof("Feedback accuracy: %.3f, Learning effectiveness: %.3f", 
		accuracy, als.stats.LearningEffectiveness)
}

// evaluateModelPerformance evaluates model performance on validation data
func (als *AdaptiveLearningSystem) evaluateModelPerformance(ctx context.Context, validationData []*TrainingExample) *PerformanceSnapshot {
	if len(validationData) == 0 {
		return &PerformanceSnapshot{
			Timestamp: time.Now(),
		}
	}
	
	var truePositives, falsePositives, trueNegatives, falseNegatives int
	
	// Evaluate each validation example
	for _, example := range validationData {
		// Create a mock threat analysis request
		request := &ThreatAnalysisRequest{
			RequestID: fmt.Sprintf("validation-%s", example.ID),
			Timestamp: time.Now(),
		}
		
		// Get model prediction
		result, err := als.threatDetector.AnalyzeRequest(ctx, request)
		if err != nil {
			continue
		}
		
		// Compare prediction with ground truth
		predicted := result.IsThreat
		actual := example.Label
		
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
	
	// Calculate metrics
	total := float64(len(validationData))
	accuracy := float64(truePositives+trueNegatives) / total
	
	precision := 0.0
	if truePositives+falsePositives > 0 {
		precision = float64(truePositives) / float64(truePositives+falsePositives)
	}
	
	recall := 0.0
	if truePositives+falseNegatives > 0 {
		recall = float64(truePositives) / float64(truePositives+falseNegatives)
	}
	
	f1Score := 0.0
	if precision+recall > 0 {
		f1Score = 2 * (precision * recall) / (precision + recall)
	}
	
	falsePositiveRate := 0.0
	if falsePositives+trueNegatives > 0 {
		falsePositiveRate = float64(falsePositives) / float64(falsePositives+trueNegatives)
	}
	
	return &PerformanceSnapshot{
		Timestamp:         time.Now(),
		Accuracy:          accuracy,
		Precision:         precision,
		Recall:            recall,
		F1Score:           f1Score,
		FalsePositiveRate: falsePositiveRate,
		ModelVersion:      "current",
		TrainingSize:      len(validationData),
		ValidationSize:    len(validationData),
	}
}

// handlePoorPerformance handles cases where model performance is below threshold
func (als *AdaptiveLearningSystem) handlePoorPerformance(ctx context.Context, performance *PerformanceSnapshot) {
	als.logger.Warn("Handling poor model performance")
	
	// Strategies for handling poor performance:
	
	// 1. Collect more training data
	als.logger.Info("Requesting more training data collection")
	
	// 2. Adjust learning parameters
	if als.config.LearningRate > 0.001 {
		als.config.LearningRate *= 0.9 // Reduce learning rate
		als.logger.Infof("Reduced learning rate to %.6f", als.config.LearningRate)
	}
	
	// 3. Increase feedback collection
	if als.config.MinFeedbackForUpdate < 100 {
		als.config.MinFeedbackForUpdate += 10
		als.logger.Infof("Increased minimum feedback requirement to %d", als.config.MinFeedbackForUpdate)
	}
	
	// 4. Alert administrators
	als.logger.Warn("Model performance degradation detected - manual review recommended")
}

// Helper methods

func (als *AdaptiveLearningSystem) convertFeedbackToTrainingExample(feedback *FeedbackExample) *TrainingExample {
	// Determine correct label based on feedback
	var label bool
	switch feedback.UserFeedback {
	case FeedbackTruePositive, FeedbackFalseNegative:
		label = true // Is a threat
	case FeedbackTrueNegative, FeedbackFalsePositive:
		label = false // Not a threat
	case FeedbackReclassify:
		label = true // Still a threat, just wrong type
	}
	
	return &TrainingExample{
		ID:         feedback.ID,
		Features:   feedback.Features,
		Label:      label,
		ThreatType: feedback.CorrectThreatType,
		Confidence: feedback.Confidence,
		Source:     string(feedback.UserFeedback),
		Timestamp:  feedback.Timestamp,
		Metadata:   feedback.Metadata,
	}
}

func (als *AdaptiveLearningSystem) balanceTrainingData(examples []*TrainingExample) []*TrainingExample {
	var positiveExamples, negativeExamples []*TrainingExample
	
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
		return examples
	}
	
	balanced := make([]*TrainingExample, 0, targetSize*2)
	
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

func (als *AdaptiveLearningSystem) splitTrainingData(examples []*TrainingExample) ([]*TrainingExample, []*TrainingExample) {
	if len(examples) < 2 {
		return examples, []*TrainingExample{}
	}
	
	// Shuffle examples
	shuffled := make([]*TrainingExample, len(examples))
	copy(shuffled, examples)
	
	// Simple shuffle
	for i := len(shuffled) - 1; i > 0; i-- {
		j := i % (i + 1) // Simple pseudo-random
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	
	splitIndex := int(float64(len(shuffled)) * als.config.ValidationSplit)
	if splitIndex == 0 {
		splitIndex = 1
	}
	if splitIndex == len(shuffled) {
		splitIndex = len(shuffled) - 1
	}
	
	trainData := shuffled[:len(shuffled)-splitIndex]
	validationData := shuffled[len(shuffled)-splitIndex:]
	
	return trainData, validationData
}

func (als *AdaptiveLearningSystem) calculateLearningEffectiveness() float64 {
	if len(als.stats.PerformanceHistory) < 2 {
		return 0.0
	}
	
	// Compare recent performance with older performance
	recent := als.stats.PerformanceHistory[len(als.stats.PerformanceHistory)-1]
	older := als.stats.PerformanceHistory[0]
	
	improvement := recent.Accuracy - older.Accuracy
	return improvement
}

// GetLearningStats returns current learning statistics
func (als *AdaptiveLearningSystem) GetLearningStats() *LearningStats {
	als.mu.RLock()
	defer als.mu.RUnlock()
	
	// Return a copy
	statsCopy := *als.stats
	statsCopy.FeedbackByType = make(map[FeedbackType]int64)
	for k, v := range als.stats.FeedbackByType {
		statsCopy.FeedbackByType[k] = v
	}
	
	statsCopy.PerformanceHistory = make([]PerformanceSnapshot, len(als.stats.PerformanceHistory))
	copy(statsCopy.PerformanceHistory, als.stats.PerformanceHistory)
	
	return &statsCopy
}

// SetConfig updates the adaptive learning configuration
func (als *AdaptiveLearningSystem) SetConfig(config *AdaptiveLearningConfig) {
	als.mu.Lock()
	defer als.mu.Unlock()
	
	als.config = config
	als.logger.Info("Updated adaptive learning configuration")
}

// GetConfig returns the current configuration
func (als *AdaptiveLearningSystem) GetConfig() *AdaptiveLearningConfig {
	als.mu.RLock()
	defer als.mu.RUnlock()
	
	configCopy := *als.config
	return &configCopy
}

// Default configurations
func getDefaultAdaptiveLearningConfig() *AdaptiveLearningConfig {
	return &AdaptiveLearningConfig{
		EnabledLearning:        true,
		FeedbackBufferSize:     1000,
		MinFeedbackForUpdate:   50,
		LearningRate:           0.01,
		RetrainingInterval:     24 * time.Hour,
		PerformanceThreshold:   0.85,
		MaxTrainingExamples:    10000,
		EnableAutoRetraining:   true,
		EnableFeedbackLearning: true,
		ValidationSplit:        0.2,
	}
}

func getDefaultLearningStats() *LearningStats {
	return &LearningStats{
		FeedbackByType:     make(map[FeedbackType]int64),
		PerformanceHistory: make([]PerformanceSnapshot, 0),
		LastUpdated:        time.Now(),
	}
}