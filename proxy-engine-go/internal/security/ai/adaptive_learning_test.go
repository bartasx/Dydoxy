package ai

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock ModelManager for testing
type MockModelManager struct {
	mock.Mock
}

func (m *MockModelManager) LoadModel(ctx context.Context, name, version string) (MLModel, error) {
	args := m.Called(ctx, name, version)
	return args.Get(0).(MLModel), args.Error(1)
}

func (m *MockModelManager) SaveModel(ctx context.Context, name, version string, model MLModel) error {
	args := m.Called(ctx, name, version, model)
	return args.Error(0)
}

func (m *MockModelManager) ListModels(ctx context.Context) ([]*ModelInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*ModelInfo), args.Error(1)
}

func (m *MockModelManager) GetLatestVersion(ctx context.Context, name string) (string, error) {
	args := m.Called(ctx, name)
	return args.String(0), args.Error(1)
}

func (m *MockModelManager) DeleteModel(ctx context.Context, name, version string) error {
	args := m.Called(ctx, name, version)
	return args.Error(0)
}

func (m *MockModelManager) SetActiveModel(ctx context.Context, name, version string) error {
	args := m.Called(ctx, name, version)
	return args.Error(0)
}

func TestAdaptiveLearningSystem_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	threatDetector := &MockAIThreatDetector{}
	modelManager := &MockModelManager{}
	
	system := NewAdaptiveLearningSystem(storage, threatDetector, modelManager, logger)
	
	assert.NotNil(t, system)
	assert.NotNil(t, system.config)
	assert.NotNil(t, system.stats)
	assert.True(t, system.config.EnabledLearning)
	assert.Equal(t, 1000, system.config.FeedbackBufferSize)
	assert.Empty(t, system.feedbackBuffer)
}

func TestAdaptiveLearningSystem_ProcessFeedback(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	threatDetector := &MockAIThreatDetector{}
	modelManager := &MockModelManager{}
	
	system := NewAdaptiveLearningSystem(storage, threatDetector, modelManager, logger)
	
	feedback := &FeedbackExample{
		ID:           "feedback-1",
		RequestID:    "req-123",
		UserFeedback: FeedbackFalsePositive,
		CorrectLabel: false,
		Features:     map[string]float64{"feature1": 1.0, "feature2": 0.5},
		Confidence:   0.8,
		Source:       "user",
		Timestamp:    time.Now(),
	}
	
	// Mock storage call
	storage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil)
	
	err := system.ProcessFeedback(context.Background(), feedback)
	require.NoError(t, err)
	
	// Verify feedback was added to buffer
	stats := system.GetLearningStats()
	assert.Equal(t, int64(1), stats.TotalFeedback)
	assert.Equal(t, int64(1), stats.FeedbackByType[FeedbackFalsePositive])
	
	storage.AssertExpectations(t)
}

func TestAdaptiveLearningSystem_ProcessFeedback_Disabled(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	threatDetector := &MockAIThreatDetector{}
	modelManager := &MockModelManager{}
	
	system := NewAdaptiveLearningSystem(storage, threatDetector, modelManager, logger)
	
	// Disable feedback learning
	config := system.GetConfig()
	config.EnableFeedbackLearning = false
	system.SetConfig(config)
	
	feedback := &FeedbackExample{
		ID:           "feedback-1",
		RequestID:    "req-123",
		UserFeedback: FeedbackFalsePositive,
		Timestamp:    time.Now(),
	}
	
	err := system.ProcessFeedback(context.Background(), feedback)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestAdaptiveLearningSystem_ConvertFeedbackToTrainingExample(t *testing.T) {
	logger := logrus.New()
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	tests := []struct {
		name         string
		feedback     *FeedbackExample
		expectedLabel bool
	}{
		{
			name: "true positive feedback",
			feedback: &FeedbackExample{
				ID:           "feedback-1",
				UserFeedback: FeedbackTruePositive,
				Features:     map[string]float64{"feature1": 1.0},
			},
			expectedLabel: true,
		},
		{
			name: "false positive feedback",
			feedback: &FeedbackExample{
				ID:           "feedback-2",
				UserFeedback: FeedbackFalsePositive,
				Features:     map[string]float64{"feature1": 0.5},
			},
			expectedLabel: false,
		},
		{
			name: "false negative feedback",
			feedback: &FeedbackExample{
				ID:           "feedback-3",
				UserFeedback: FeedbackFalseNegative,
				Features:     map[string]float64{"feature1": 0.8},
			},
			expectedLabel: true,
		},
		{
			name: "reclassify feedback",
			feedback: &FeedbackExample{
				ID:           "feedback-4",
				UserFeedback: FeedbackReclassify,
				Features:     map[string]float64{"feature1": 0.9},
			},
			expectedLabel: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			example := system.convertFeedbackToTrainingExample(tt.feedback)
			assert.Equal(t, tt.expectedLabel, example.Label)
			assert.Equal(t, tt.feedback.ID, example.ID)
			assert.Equal(t, tt.feedback.Features, example.Features)
			assert.Equal(t, string(tt.feedback.UserFeedback), example.Source)
		})
	}
}

func TestAdaptiveLearningSystem_BalanceTrainingData(t *testing.T) {
	logger := logrus.New()
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	// Create imbalanced data (more negative than positive)
	examples := []*TrainingExample{
		{ID: "pos-1", Label: true},
		{ID: "pos-2", Label: true},
		{ID: "neg-1", Label: false},
		{ID: "neg-2", Label: false},
		{ID: "neg-3", Label: false},
		{ID: "neg-4", Label: false},
	}
	
	balanced := system.balanceTrainingData(examples)
	
	// Should have equal numbers of positive and negative examples
	positiveCount := 0
	negativeCount := 0
	for _, example := range balanced {
		if example.Label {
			positiveCount++
		} else {
			negativeCount++
		}
	}
	
	assert.Equal(t, positiveCount, negativeCount)
	assert.Equal(t, 2, positiveCount) // Should be limited by smaller class
	assert.Len(t, balanced, 4)
}

func TestAdaptiveLearningSystem_SplitTrainingData(t *testing.T) {
	logger := logrus.New()
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	examples := []*TrainingExample{
		{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}, {ID: "5"},
		{ID: "6"}, {ID: "7"}, {ID: "8"}, {ID: "9"}, {ID: "10"},
	}
	
	trainData, validationData := system.splitTrainingData(examples)
	
	// With default 0.2 validation split, should have 8 train and 2 validation
	assert.Len(t, trainData, 8)
	assert.Len(t, validationData, 2)
	assert.Equal(t, len(examples), len(trainData)+len(validationData))
}

func TestAdaptiveLearningSystem_Configuration(t *testing.T) {
	logger := logrus.New()
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	// Test default configuration
	config := system.GetConfig()
	assert.True(t, config.EnabledLearning)
	assert.Equal(t, 1000, config.FeedbackBufferSize)
	assert.Equal(t, 50, config.MinFeedbackForUpdate)
	assert.Equal(t, 0.01, config.LearningRate)
	
	// Test updating configuration
	newConfig := &AdaptiveLearningConfig{
		EnabledLearning:        false,
		FeedbackBufferSize:     500,
		MinFeedbackForUpdate:   25,
		LearningRate:           0.005,
		RetrainingInterval:     12 * time.Hour,
		PerformanceThreshold:   0.9,
		MaxTrainingExamples:    5000,
		EnableAutoRetraining:   false,
		EnableFeedbackLearning: false,
		ValidationSplit:        0.3,
	}
	
	system.SetConfig(newConfig)
	updatedConfig := system.GetConfig()
	
	assert.False(t, updatedConfig.EnabledLearning)
	assert.Equal(t, 500, updatedConfig.FeedbackBufferSize)
	assert.Equal(t, 25, updatedConfig.MinFeedbackForUpdate)
	assert.Equal(t, 0.005, updatedConfig.LearningRate)
	assert.Equal(t, 12*time.Hour, updatedConfig.RetrainingInterval)
	assert.Equal(t, 0.9, updatedConfig.PerformanceThreshold)
	assert.False(t, updatedConfig.EnableAutoRetraining)
	assert.False(t, updatedConfig.EnableFeedbackLearning)
	assert.Equal(t, 0.3, updatedConfig.ValidationSplit)
}

func TestAdaptiveLearningSystem_LearningStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	threatDetector := &MockAIThreatDetector{}
	modelManager := &MockModelManager{}
	
	system := NewAdaptiveLearningSystem(storage, threatDetector, modelManager, logger)
	
	// Process some feedback
	feedbacks := []*FeedbackExample{
		{ID: "f1", UserFeedback: FeedbackTruePositive, Timestamp: time.Now()},
		{ID: "f2", UserFeedback: FeedbackFalsePositive, Timestamp: time.Now()},
		{ID: "f3", UserFeedback: FeedbackTruePositive, Timestamp: time.Now()},
	}
	
	storage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil).Times(3)
	
	for _, feedback := range feedbacks {
		err := system.ProcessFeedback(context.Background(), feedback)
		require.NoError(t, err)
	}
	
	stats := system.GetLearningStats()
	assert.Equal(t, int64(3), stats.TotalFeedback)
	assert.Equal(t, int64(2), stats.FeedbackByType[FeedbackTruePositive])
	assert.Equal(t, int64(1), stats.FeedbackByType[FeedbackFalsePositive])
	
	storage.AssertExpectations(t)
}

func TestAdaptiveLearningSystem_CalculateLearningEffectiveness(t *testing.T) {
	logger := logrus.New()
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	// No history should return 0
	effectiveness := system.calculateLearningEffectiveness()
	assert.Equal(t, 0.0, effectiveness)
	
	// Add performance history
	system.stats.PerformanceHistory = []PerformanceSnapshot{
		{Timestamp: time.Now().Add(-24 * time.Hour), Accuracy: 0.8},
		{Timestamp: time.Now().Add(-12 * time.Hour), Accuracy: 0.85},
		{Timestamp: time.Now(), Accuracy: 0.9},
	}
	
	effectiveness = system.calculateLearningEffectiveness()
	assert.Equal(t, 0.1, effectiveness) // 0.9 - 0.8 = 0.1 improvement
}

func TestAdaptiveLearningSystem_HandlePoorPerformance(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	system := NewAdaptiveLearningSystem(nil, nil, nil, logger)
	
	originalLearningRate := system.config.LearningRate
	originalMinFeedback := system.config.MinFeedbackForUpdate
	
	performance := &PerformanceSnapshot{
		Accuracy: 0.6, // Below default threshold of 0.85
	}
	
	system.handlePoorPerformance(context.Background(), performance)
	
	// Should have adjusted parameters
	assert.Less(t, system.config.LearningRate, originalLearningRate)
	assert.Greater(t, system.config.MinFeedbackForUpdate, originalMinFeedback)
}