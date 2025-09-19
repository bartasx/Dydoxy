package ai

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDefaultThreatDetector_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	// Mock storage calls for initialization
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.policies)
	assert.NotNil(t, detector.stats)
	assert.True(t, detector.policies.GlobalEnabled)
	
	storage.AssertExpectations(t)
}

func TestDefaultThreatDetector_AnalyzeRequest_AIDisabled(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	// Disable AI
	detector.policies.GlobalEnabled = false
	
	request := &ThreatAnalysisRequest{
		RequestID: "test-req-1",
		SourceIP:  net.ParseIP("192.168.1.1"),
		URL:       "https://example.com/test",
		Method:    "GET",
		Timestamp: time.Now(),
	}
	
	result, err := detector.AnalyzeRequest(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)
	
	assert.Equal(t, "test-req-1", result.RequestID)
	assert.False(t, result.IsThreat)
	assert.Equal(t, ThreatLevelLow, result.ThreatLevel)
	assert.Equal(t, 0.0, result.Confidence)
	assert.Equal(t, ActionAllow, result.RecommendedAction)
	assert.Contains(t, result.Reason, "disabled")
	
	storage.AssertExpectations(t)
}
// Mock B
ehavioralAnalyzer for testing
type MockBehavioralAnalyzer struct {
	mock.Mock
}

func (m *MockBehavioralAnalyzer) AnalyzeBehavior(ctx context.Context, subject string, request *RequestContext) (*BehaviorAnalysis, error) {
	args := m.Called(ctx, subject, request)
	return args.Get(0).(*BehaviorAnalysis), args.Error(1)
}

func (m *MockBehavioralAnalyzer) UpdateProfile(ctx context.Context, subject string, request *RequestContext) error {
	args := m.Called(ctx, subject, request)
	return args.Error(0)
}

func (m *MockBehavioralAnalyzer) GetProfile(ctx context.Context, subject string) (*BehaviorProfile, error) {
	args := m.Called(ctx, subject)
	return args.Get(0).(*BehaviorProfile), args.Error(1)
}

func (m *MockBehavioralAnalyzer) DetectAnomalies(ctx context.Context, subject string, request *RequestContext) (bool, float64, error) {
	args := m.Called(ctx, subject, request)
	return args.Bool(0), args.Get(1).(float64), args.Error(2)
}

func (m *MockBehavioralAnalyzer) TrainModel(ctx context.Context, data []*RequestContext) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

// Mock MLModel for testing
type MockMLModel struct {
	mock.Mock
}

func (m *MockMLModel) Predict(ctx context.Context, features map[string]float64) (*MLPrediction, error) {
	args := m.Called(ctx, features)
	return args.Get(0).(*MLPrediction), args.Error(1)
}

func (m *MockMLModel) Train(ctx context.Context, examples []*TrainingExample) error {
	args := m.Called(ctx, examples)
	return args.Error(0)
}

func (m *MockMLModel) GetMetrics(ctx context.Context) (*ModelMetrics, error) {
	args := m.Called(ctx)
	return args.Get(0).(*ModelMetrics), args.Error(1)
}

func (m *MockMLModel) Export(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockMLModel) Import(ctx context.Context, data []byte) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockMLModel) GetVersion() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockMLModel) IsReady() bool {
	args := m.Called()
	return args.Bool(0)
}

func TestDefaultThreatDetector_AnalyzeRequest_WithMLModel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	contentModel := &MockMLModel{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	storage.On("SaveThreatAnalysis", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisResult")).Return(nil)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	detector.SetContentModel(contentModel)
	
	request := &ThreatAnalysisRequest{
		RequestID: "test-req-2",
		SourceIP:  net.ParseIP("192.168.1.1"),
		URL:       "https://malicious.com/test",
		Method:    "GET",
		UserAgent: "suspicious-bot",
		Timestamp: time.Now(),
	}
	
	// Mock feature extraction
	features := &FeatureVector{
		URLLength:    25,
		URLEntropy:   4.5,
		Features:     map[string]float64{"suspicious": 1.0},
	}
	featureExtractor.On("ExtractFeatures", mock.Anything, request).Return(features, nil)
	
	// Mock ML model prediction
	mlPrediction := &MLPrediction{
		ModelName:    "content-model",
		ModelVersion: "1.0.0",
		IsThreat:     true,
		Confidence:   0.85,
		ThreatType:   ThreatTypeMalware,
		Timestamp:    time.Now(),
	}
	contentModel.On("Predict", mock.Anything, mock.AnythingOfType("map[string]float64")).Return(mlPrediction, nil)
	
	// Mock behavioral analysis
	behaviorAnalysis := &BehaviorAnalysis{
		Subject:        "ip:192.168.1.1",
		IsAnomalous:    false,
		AnomalyScore:   0.3,
		AnomalyReasons: []string{},
		Timestamp:      time.Now(),
	}
	behavioralAnalyzer.On("AnalyzeBehavior", mock.Anything, "ip:192.168.1.1", mock.AnythingOfType("*ai.RequestContext")).Return(behaviorAnalysis, nil)
	
	result, err := detector.AnalyzeRequest(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)
	
	assert.Equal(t, "test-req-2", result.RequestID)
	assert.True(t, result.IsThreat)
	assert.Equal(t, ThreatTypeMalware, result.ThreatType)
	assert.Equal(t, ThreatLevelHigh, result.ThreatLevel)
	assert.Equal(t, 0.85, result.Confidence)
	assert.Equal(t, ActionBlock, result.RecommendedAction)
	assert.Len(t, result.MLPredictions, 1)
	assert.NotNil(t, result.BehaviorAnalysis)
	
	storage.AssertExpectations(t)
	featureExtractor.AssertExpectations(t)
	behavioralAnalyzer.AssertExpectations(t)
	contentModel.AssertExpectations(t)
}f
unc TestDefaultThreatDetector_AnalyzeRequest_BehavioralAnomaly(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	storage.On("SaveThreatAnalysis", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisResult")).Return(nil)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	request := &ThreatAnalysisRequest{
		RequestID: "test-req-3",
		SourceIP:  net.ParseIP("192.168.1.1"),
		URL:       "https://example.com/test",
		Method:    "GET",
		UserID:    "user123",
		Timestamp: time.Now(),
	}
	
	// Mock feature extraction
	features := &FeatureVector{
		URLLength: 20,
		Features:  map[string]float64{"normal": 1.0},
	}
	featureExtractor.On("ExtractFeatures", mock.Anything, request).Return(features, nil)
	
	// Mock behavioral analysis with anomaly
	behaviorAnalysis := &BehaviorAnalysis{
		Subject:        "user:user123",
		IsAnomalous:    true,
		AnomalyScore:   0.8,
		AnomalyReasons: []string{"Unusual request frequency", "Inconsistent user agent"},
		Timestamp:      time.Now(),
	}
	behavioralAnalyzer.On("AnalyzeBehavior", mock.Anything, "user:user123", mock.AnythingOfType("*ai.RequestContext")).Return(behaviorAnalysis, nil)
	
	result, err := detector.AnalyzeRequest(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)
	
	assert.Equal(t, "test-req-3", result.RequestID)
	assert.True(t, result.IsThreat)
	assert.Equal(t, ThreatTypeAnomalous, result.ThreatType)
	assert.Equal(t, ThreatLevelHigh, result.ThreatLevel)
	assert.Equal(t, 0.8, result.Confidence)
	assert.Equal(t, ActionChallenge, result.RecommendedAction)
	assert.Contains(t, result.Reason, "Anomalous behavior detected")
	
	storage.AssertExpectations(t)
	featureExtractor.AssertExpectations(t)
	behavioralAnalyzer.AssertExpectations(t)
}

func TestDefaultThreatDetector_UpdateModels(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	contentModel := &MockMLModel{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	detector.SetContentModel(contentModel)
	
	trainingData := []*TrainingExample{
		{
			ID:       "example-1",
			Features: map[string]float64{"feature1": 1.0, "feature2": 0.5},
			Label:    true,
			Source:   "manual",
			Timestamp: time.Now(),
		},
		{
			ID:       "example-2",
			Features: map[string]float64{"feature1": 0.3, "feature2": 0.8},
			Label:    false,
			Source:   "automated",
			Timestamp: time.Now(),
		},
	}
	
	// Mock model training
	contentModel.On("Train", mock.Anything, trainingData).Return(nil)
	contentModel.On("GetMetrics", mock.Anything).Return(&ModelMetrics{Accuracy: 0.92}, nil)
	contentModel.On("GetVersion").Return("1.0.0")
	
	// Mock behavioral analyzer training
	behavioralAnalyzer.On("TrainModel", mock.Anything, mock.AnythingOfType("[]*ai.RequestContext")).Return(nil)
	
	err := detector.UpdateModels(context.Background(), trainingData)
	require.NoError(t, err)
	
	contentModel.AssertExpectations(t)
	behavioralAnalyzer.AssertExpectations(t)
}

func TestDefaultThreatDetector_GetThreatIntelligence(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	query := &ThreatQuery{
		Type:      "domain",
		Value:     "example.com",
		Timestamp: time.Now(),
	}
	
	intelligence, err := detector.GetThreatIntelligence(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, intelligence)
	
	assert.Equal(t, query, intelligence.Query)
	assert.False(t, intelligence.IsThreat) // No threat patterns implemented in placeholder
	assert.NotNil(t, intelligence.Patterns)
	
	storage.AssertExpectations(t)
}

func TestDefaultThreatDetector_ConfigurePolicies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	storage.On("SaveThreatPolicies", mock.Anything, mock.AnythingOfType("*ai.ThreatPolicies")).Return(nil)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	newPolicies := &ThreatPolicies{
		GlobalEnabled:       true,
		ConfidenceThreshold: 0.8,
		ThreatLevelThresholds: map[ThreatLevel]float64{
			ThreatLevelHigh: 0.9,
		},
		ActionPolicies: map[ThreatType]ActionType{
			ThreatTypeMalware: ActionBlock,
		},
		BehavioralAnalysis: false,
		MachineLearning:    true,
		ThreatIntelligence: true,
		AlertingEnabled:    true,
		AlertThreshold:     ThreatLevelHigh,
	}
	
	err := detector.ConfigurePolicies(context.Background(), newPolicies)
	require.NoError(t, err)
	
	// Verify policies were updated
	assert.Equal(t, 0.8, detector.policies.ConfidenceThreshold)
	assert.False(t, detector.policies.BehavioralAnalysis)
	
	storage.AssertExpectations(t)
}func Tes
tDefaultThreatDetector_GetStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	
	// Manually update some stats for testing
	detector.stats.TotalRequests = 100
	detector.stats.ThreatsDetected = 15
	detector.stats.ThreatsByType[ThreatTypeMalware] = 10
	detector.stats.ThreatsByLevel[ThreatLevelHigh] = 8
	detector.stats.ActionsTaken[ActionBlock] = 12
	detector.stats.ModelAccuracy["content-model"] = 0.92
	
	stats, err := detector.GetStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	
	assert.Equal(t, int64(100), stats.TotalRequests)
	assert.Equal(t, int64(15), stats.ThreatsDetected)
	assert.Equal(t, int64(10), stats.ThreatsByType[ThreatTypeMalware])
	assert.Equal(t, int64(8), stats.ThreatsByLevel[ThreatLevelHigh])
	assert.Equal(t, int64(12), stats.ActionsTaken[ActionBlock])
	assert.Equal(t, 0.92, stats.ModelAccuracy["content-model"])
	
	// Verify it's a copy (modifying returned stats shouldn't affect original)
	stats.TotalRequests = 999
	assert.Equal(t, int64(100), detector.stats.TotalRequests)
	
	storage.AssertExpectations(t)
}

func TestDefaultThreatDetector_GetHealth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	behavioralAnalyzer := &MockBehavioralAnalyzer{}
	contentModel := &MockMLModel{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return(&AIThreatStats{}, nil) // For health check
	
	detector := NewDefaultThreatDetector(storage, featureExtractor, behavioralAnalyzer, logger)
	detector.SetContentModel(contentModel)
	
	contentModel.On("IsReady").Return(true)
	
	health, err := detector.GetHealth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, health)
	
	assert.Equal(t, "healthy", health.Overall)
	assert.Equal(t, "healthy", health.Components["storage"])
	assert.Equal(t, "healthy", health.Components["feature_extractor"])
	assert.Equal(t, "healthy", health.Components["behavioral_analyzer"])
	assert.Equal(t, "ready", health.ModelStatus["content_model"])
	assert.Contains(t, health.Metrics, "total_requests")
	assert.Contains(t, health.Metrics, "threats_detected")
	
	storage.AssertExpectations(t)
	contentModel.AssertExpectations(t)
}

func TestDefaultThreatDetector_GetHealth_Degraded(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	contentModel := &MockMLModel{}
	
	storage.On("LoadThreatPolicies", mock.Anything).Return((*ThreatPolicies)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError)
	storage.On("LoadAIStats", mock.Anything).Return((*AIThreatStats)(nil), assert.AnError) // Storage error for health check
	
	// Create detector with missing components
	detector := NewDefaultThreatDetector(storage, nil, nil, logger)
	detector.SetContentModel(contentModel)
	
	contentModel.On("IsReady").Return(false)
	
	health, err := detector.GetHealth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, health)
	
	assert.Equal(t, "degraded", health.Overall)
	assert.Equal(t, "unhealthy", health.Components["storage"])
	assert.Equal(t, "unavailable", health.Components["feature_extractor"])
	assert.Equal(t, "unavailable", health.Components["behavioral_analyzer"])
	assert.Equal(t, "not_ready", health.ModelStatus["content_model"])
	assert.NotEmpty(t, health.Issues)
	
	storage.AssertExpectations(t)
	contentModel.AssertExpectations(t)
}

func TestDefaultThreatDetector_ThreatLevelCalculation(t *testing.T) {
	logger := logrus.New()
	detector := NewDefaultThreatDetector(nil, nil, nil, logger)
	
	tests := []struct {
		confidence float64
		expected   ThreatLevel
	}{
		{0.95, ThreatLevelCritical},
		{0.85, ThreatLevelHigh},
		{0.65, ThreatLevelMedium},
		{0.3, ThreatLevelLow},
		{0.1, ThreatLevelLow},
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("confidence_%.2f", tt.confidence), func(t *testing.T) {
			level := detector.calculateThreatLevel(tt.confidence)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestDefaultThreatDetector_CombineReasons(t *testing.T) {
	logger := logrus.New()
	detector := NewDefaultThreatDetector(nil, nil, nil, logger)
	
	tests := []struct {
		name     string
		reasons  []string
		expected string
	}{
		{
			name:     "no reasons",
			reasons:  []string{},
			expected: "No specific reason",
		},
		{
			name:     "single reason",
			reasons:  []string{"ML model detected malware"},
			expected: "ML model detected malware",
		},
		{
			name:     "multiple reasons",
			reasons:  []string{"ML detected malware", "Behavioral anomaly", "Threat pattern matched"},
			expected: "ML detected malware; Behavioral anomaly; Threat pattern matched",
		},
		{
			name:     "many reasons",
			reasons:  []string{"Reason 1", "Reason 2", "Reason 3", "Reason 4", "Reason 5"},
			expected: "Reason 1; Reason 2; Reason 3 (and 2 more)",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.combineReasons(tt.reasons)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultThreatDetector_GetSubjectIdentifier(t *testing.T) {
	logger := logrus.New()
	detector := NewDefaultThreatDetector(nil, nil, nil, logger)
	
	tests := []struct {
		name     string
		request  *ThreatAnalysisRequest
		expected string
	}{
		{
			name: "with user ID",
			request: &ThreatAnalysisRequest{
				UserID:   "user123",
				SourceIP: net.ParseIP("192.168.1.1"),
			},
			expected: "user:user123",
		},
		{
			name: "with IP only",
			request: &ThreatAnalysisRequest{
				SourceIP: net.ParseIP("192.168.1.1"),
			},
			expected: "ip:192.168.1.1",
		},
		{
			name:     "no identifier",
			request:  &ThreatAnalysisRequest{},
			expected: "unknown",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.getSubjectIdentifier(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}