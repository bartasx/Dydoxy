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

// Mock AIStorage for testing
type MockAIStorage struct {
	mock.Mock
}

func (m *MockAIStorage) SaveBehaviorProfile(ctx context.Context, subject string, profile *BehaviorProfile) error {
	args := m.Called(ctx, subject, profile)
	return args.Error(0)
}

func (m *MockAIStorage) LoadBehaviorProfile(ctx context.Context, subject string) (*BehaviorProfile, error) {
	args := m.Called(ctx, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*BehaviorProfile), args.Error(1)
}

// Implement other required methods (simplified for testing)
func (m *MockAIStorage) SaveModel(ctx context.Context, name, version string, data []byte) error {
	return nil
}
func (m *MockAIStorage) LoadModel(ctx context.Context, name, version string) ([]byte, error) {
	return nil, nil
}
func (m *MockAIStorage) ListModels(ctx context.Context) ([]*ModelInfo, error) {
	return nil, nil
}
func (m *MockAIStorage) DeleteModel(ctx context.Context, name, version string) error {
	return nil
}
func (m *MockAIStorage) SaveTrainingExample(ctx context.Context, example *TrainingExample) error {
	return nil
}
func (m *MockAIStorage) LoadTrainingExamples(ctx context.Context, limit int, offset int) ([]*TrainingExample, error) {
	return nil, nil
}
func (m *MockAIStorage) SaveThreatAnalysis(ctx context.Context, result *ThreatAnalysisResult) error {
	return nil
}
func (m *MockAIStorage) LoadThreatAnalysis(ctx context.Context, requestID string) (*ThreatAnalysisResult, error) {
	return nil, nil
}
func (m *MockAIStorage) SaveAIStats(ctx context.Context, stats *AIThreatStats) error {
	return nil
}
func (m *MockAIStorage) LoadAIStats(ctx context.Context) (*AIThreatStats, error) {
	return nil, nil
}
func (m *MockAIStorage) SaveThreatPolicies(ctx context.Context, policies *ThreatPolicies) error {
	return nil
}
func (m *MockAIStorage) LoadThreatPolicies(ctx context.Context) (*ThreatPolicies, error) {
	return nil, nil
}

func TestDefaultBehavioralAnalyzer_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	assert.NotNil(t, analyzer)
	assert.NotNil(t, analyzer.config)
	assert.NotNil(t, analyzer.profiles)
	assert.True(t, analyzer.config.EnableLearning)
	assert.Equal(t, 0.7, analyzer.config.AnomalyThreshold)
}

func TestDefaultBehavioralAnalyzer_NewProfile(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Now(),
	}
	
	// Mock storage to return "not found" for new profile
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return((*BehaviorProfile)(nil), assert.AnError)
	
	analysis, err := analyzer.AnalyzeBehavior(context.Background(), "user:user123", request)
	require.NoError(t, err)
	require.NotNil(t, analysis)
	
	assert.Equal(t, "user:user123", analysis.Subject)
	assert.NotNil(t, analysis.Profile)
	assert.Equal(t, int64(1), analysis.Profile.RequestCount)
	assert.Equal(t, 50.0, analysis.Profile.TrustScore) // Default trust score
	assert.Contains(t, analysis.Profile.CommonUserAgents, request.UserAgent)
	assert.Contains(t, analysis.Profile.CommonPaths, request.Path)
	assert.Contains(t, analysis.Profile.GeoLocations, request.Country)
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_ExistingProfile(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	// Create existing profile
	existingProfile := &BehaviorProfile{
		Subject:          "user:user123",
		FirstSeen:        time.Now().Add(-24 * time.Hour),
		LastSeen:         time.Now().Add(-1 * time.Hour),
		RequestCount:     50,
		AverageFrequency: 2.0,
		CommonUserAgents: []string{"Mozilla/5.0"},
		CommonPaths:      []string{"/api/users", "/dashboard"},
		TimePatterns:     map[int]int64{9: 10, 14: 15, 16: 20},
		GeoLocations:     []string{"US"},
		TrustScore:       75.0,
		ViolationCount:   0,
		UpdatedAt:        time.Now().Add(-1 * time.Hour),
	}
	
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0",
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Date(2023, 12, 15, 14, 30, 0, 0, time.UTC), // 2:30 PM
	}
	
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return(existingProfile, nil)
	
	analysis, err := analyzer.AnalyzeBehavior(context.Background(), "user:user123", request)
	require.NoError(t, err)
	require.NotNil(t, analysis)
	
	assert.Equal(t, "user:user123", analysis.Subject)
	assert.False(t, analysis.IsAnomalous) // Should be normal behavior
	assert.Less(t, analysis.AnomalyScore, 0.7) // Below threshold
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_AnomalousFrequency(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	// Create profile with normal frequency
	existingProfile := &BehaviorProfile{
		Subject:          "user:user123",
		FirstSeen:        time.Now().Add(-24 * time.Hour),
		LastSeen:         time.Now().Add(-1 * time.Hour),
		RequestCount:     24, // 1 request per hour
		AverageFrequency: 1.0,
		CommonUserAgents: []string{"Mozilla/5.0"},
		CommonPaths:      []string{"/api/users"},
		TimePatterns:     map[int]int64{9: 5, 14: 10, 16: 9},
		GeoLocations:     []string{"US"},
		TrustScore:       75.0,
		ViolationCount:   0,
		UpdatedAt:        time.Now().Add(-1 * time.Hour),
	}
	
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0",
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Now(),
	}
	
	// Simulate high frequency by updating profile
	existingProfile.AverageFrequency = 150.0 // Very high frequency
	
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return(existingProfile, nil)
	
	analysis, err := analyzer.AnalyzeBehavior(context.Background(), "user:user123", request)
	require.NoError(t, err)
	require.NotNil(t, analysis)
	
	assert.True(t, analysis.IsAnomalous)
	assert.Greater(t, analysis.AnomalyScore, 0.7)
	assert.Contains(t, analysis.AnomalyReasons, "Unusual request frequency")
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_AnomalousLocation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	// Create profile with US location history
	existingProfile := &BehaviorProfile{
		Subject:          "user:user123",
		FirstSeen:        time.Now().Add(-24 * time.Hour),
		LastSeen:         time.Now().Add(-1 * time.Hour),
		RequestCount:     50,
		AverageFrequency: 2.0,
		CommonUserAgents: []string{"Mozilla/5.0"},
		CommonPaths:      []string{"/api/users"},
		TimePatterns:     map[int]int64{9: 10, 14: 15, 16: 20},
		GeoLocations:     []string{"US"}, // Only US
		TrustScore:       75.0,
		ViolationCount:   0,
		UpdatedAt:        time.Now().Add(-1 * time.Hour),
	}
	
	// Request from different country
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0",
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "CN", // Different country
		Timestamp: time.Now(),
	}
	
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return(existingProfile, nil)
	
	analysis, err := analyzer.AnalyzeBehavior(context.Background(), "user:user123", request)
	require.NoError(t, err)
	require.NotNil(t, analysis)
	
	assert.True(t, analysis.IsAnomalous)
	assert.Contains(t, analysis.AnomalyReasons, "Unusual geographic location")
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_AnomalousUserAgent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	// Create profile with consistent user agent
	existingProfile := &BehaviorProfile{
		Subject:          "user:user123",
		FirstSeen:        time.Now().Add(-24 * time.Hour),
		LastSeen:         time.Now().Add(-1 * time.Hour),
		RequestCount:     50,
		AverageFrequency: 2.0,
		CommonUserAgents: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		CommonPaths:      []string{"/api/users"},
		TimePatterns:     map[int]int64{9: 10, 14: 15, 16: 20},
		GeoLocations:     []string{"US"},
		TrustScore:       75.0,
		ViolationCount:   0,
		UpdatedAt:        time.Now().Add(-1 * time.Hour),
	}
	
	// Request with completely different user agent
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "curl/7.68.0", // Very different user agent
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Now(),
	}
	
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return(existingProfile, nil)
	
	analysis, err := analyzer.AnalyzeBehavior(context.Background(), "user:user123", request)
	require.NoError(t, err)
	require.NotNil(t, analysis)
	
	assert.True(t, analysis.IsAnomalous)
	assert.Contains(t, analysis.AnomalyReasons, "Inconsistent user agent")
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_UpdateProfile(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0",
		Method:    "GET",
		Path:      "/api/users",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Now(),
	}
	
	// Mock storage to return "not found" initially
	storage.On("LoadBehaviorProfile", mock.Anything, "user:user123").Return((*BehaviorProfile)(nil), assert.AnError)
	
	err := analyzer.UpdateProfile(context.Background(), "user:user123", request)
	require.NoError(t, err)
	
	// Verify profile was created and cached
	profile, err := analyzer.GetProfile(context.Background(), "user:user123")
	require.NoError(t, err)
	assert.Equal(t, int64(1), profile.RequestCount)
	assert.Contains(t, profile.CommonUserAgents, request.UserAgent)
	
	// Update with another request
	request2 := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0",
		Method:    "POST",
		Path:      "/api/posts",
		UserID:    "user123",
		Country:   "US",
		Timestamp: time.Now(),
	}
	
	err = analyzer.UpdateProfile(context.Background(), "user:user123", request2)
	require.NoError(t, err)
	
	// Verify profile was updated
	profile, err = analyzer.GetProfile(context.Background(), "user:user123")
	require.NoError(t, err)
	assert.Equal(t, int64(2), profile.RequestCount)
	assert.Contains(t, profile.CommonPaths, "/api/posts")
	
	storage.AssertExpectations(t)
}

func TestDefaultBehavioralAnalyzer_TrainModel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	featureExtractor := &MockFeatureExtractor{}
	
	analyzer := NewDefaultBehavioralAnalyzer(storage, featureExtractor, logger)
	
	// Create training data
	trainingData := []*RequestContext{
		{
			SourceIP:  net.ParseIP("192.168.1.1"),
			UserAgent: "Mozilla/5.0",
			Method:    "GET",
			Path:      "/api/users",
			UserID:    "user1",
			Country:   "US",
			Timestamp: time.Now().Add(-1 * time.Hour),
		},
		{
			SourceIP:  net.ParseIP("192.168.1.1"),
			UserAgent: "Mozilla/5.0",
			Method:    "GET",
			Path:      "/api/posts",
			UserID:    "user1",
			Country:   "US",
			Timestamp: time.Now(),
		},
		{
			SourceIP:  net.ParseIP("192.168.1.2"),
			UserAgent: "Chrome/91.0",
			Method:    "GET",
			Path:      "/dashboard",
			UserID:    "user2",
			Country:   "CA",
			Timestamp: time.Now().Add(-30 * time.Minute),
		},
	}
	
	// Mock storage calls (training will try to save profiles)
	storage.On("LoadBehaviorProfile", mock.Anything, mock.AnythingOfType("string")).Return((*BehaviorProfile)(nil), assert.AnError).Maybe()
	storage.On("SaveBehaviorProfile", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*ai.BehaviorProfile")).Return(nil).Maybe()
	
	err := analyzer.TrainModel(context.Background(), trainingData)
	require.NoError(t, err)
	
	// Verify profiles were created
	stats := analyzer.GetStats()
	assert.Greater(t, stats["total_profiles"].(int), 0)
}

func TestDefaultBehavioralAnalyzer_TimePatternScore(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	analyzer := NewDefaultBehavioralAnalyzer(nil, nil, logger)
	
	// Create profile with strong 9 AM pattern
	profile := &BehaviorProfile{
		TimePatterns: map[int]int64{
			9:  50, // Strong pattern at 9 AM
			10: 5,
			14: 10,
		},
	}
	
	// Request at 9 AM should have high score
	request9AM := &RequestContext{
		Timestamp: time.Date(2023, 12, 15, 9, 0, 0, 0, time.UTC),
	}
	score := analyzer.calculateTimePatternScore(profile, request9AM)
	assert.Greater(t, score, 0.7) // Should be high
	
	// Request at 3 AM should have low score
	request3AM := &RequestContext{
		Timestamp: time.Date(2023, 12, 15, 3, 0, 0, 0, time.UTC),
	}
	score = analyzer.calculateTimePatternScore(profile, request3AM)
	assert.Equal(t, 0.0, score) // Should be 0 (no pattern)
}

func TestDefaultBehavioralAnalyzer_StringSimilarity(t *testing.T) {
	logger := logrus.New()
	analyzer := NewDefaultBehavioralAnalyzer(nil, nil, logger)
	
	tests := []struct {
		s1       string
		s2       string
		expected float64
	}{
		{"identical", "identical", 1.0},
		{"Mozilla/5.0", "Mozilla/5.1", 0.9}, // High similarity
		{"Chrome", "Firefox", 0.0},          // No similarity
		{"", "test", 0.0},                   // Empty string
		{"test", "", 0.0},                   // Empty string
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s vs %s", tt.s1, tt.s2), func(t *testing.T) {
			similarity := analyzer.calculateStringSimilarity(tt.s1, tt.s2)
			assert.InDelta(t, tt.expected, similarity, 0.1)
		})
	}
}

func TestDefaultBehavioralAnalyzer_Configuration(t *testing.T) {
	logger := logrus.New()
	analyzer := NewDefaultBehavioralAnalyzer(nil, nil, logger)
	
	// Test default configuration
	config := analyzer.GetConfig()
	assert.True(t, config.EnableLearning)
	assert.Equal(t, 0.7, config.AnomalyThreshold)
	assert.Equal(t, 10, config.MinRequestsForProfile)
	
	// Test updating configuration
	newConfig := &BehavioralConfig{
		ProfileTTL:            7 * 24 * time.Hour,
		MinRequestsForProfile: 20,
		AnomalyThreshold:      0.8,
		UpdateInterval:        10 * time.Minute,
		MaxProfileSize:        500,
		EnableLearning:        false,
		SensitivityLevel:      1.5,
	}
	
	analyzer.SetConfig(newConfig)
	updatedConfig := analyzer.GetConfig()
	
	assert.False(t, updatedConfig.EnableLearning)
	assert.Equal(t, 0.8, updatedConfig.AnomalyThreshold)
	assert.Equal(t, 20, updatedConfig.MinRequestsForProfile)
	assert.Equal(t, 1.5, updatedConfig.SensitivityLevel)
}

func TestDefaultBehavioralAnalyzer_Statistics(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAIStorage{}
	analyzer := NewDefaultBehavioralAnalyzer(storage, nil, logger)
	
	// Initially no profiles
	stats := analyzer.GetStats()
	assert.Equal(t, 0, stats["total_profiles"])
	assert.Equal(t, 0.0, stats["average_trust_score"])
	
	// Add some profiles manually for testing
	analyzer.profiles["user1"] = &BehaviorProfile{
		RequestCount: 10,
		TrustScore:   80.0,
	}
	analyzer.profiles["user2"] = &BehaviorProfile{
		RequestCount: 20,
		TrustScore:   60.0,
	}
	
	stats = analyzer.GetStats()
	assert.Equal(t, 2, stats["total_profiles"])
	assert.Equal(t, int64(30), stats["total_requests"])
	assert.Equal(t, 70.0, stats["average_trust_score"]) // (80+60)/2
}

func TestDefaultBehavioralAnalyzer_DetectAnomalies(t *testing.T) {
	logger := logrus.New()
	analyzer := NewDefaultBehavioralAnalyzer(nil, nil, logger)
	
	request := &RequestContext{
		SourceIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "curl/7.68.0",
		Timestamp: time.Now(),
		Country:   "CN",
	}
	
	// Profile with low trust and violations
	profile := &BehaviorProfile{
		AverageFrequency: 1.0,
		TrustScore:       20.0, // Low trust
		ViolationCount:   10,   // High violations
		TimePatterns:     map[int]int64{9: 10},
		CommonUserAgents: []string{"Mozilla/5.0"},
		GeoLocations:     []string{"US"},
	}
	
	metrics := analyzer.calculateBehavioralMetrics(profile, request)
	score, reasons := analyzer.detectAnomalies(profile, request, metrics)
	
	assert.Greater(t, score, 0.5) // Should detect anomalies
	assert.NotEmpty(t, reasons)
	assert.Contains(t, reasons, "Low trust score")
	assert.Contains(t, reasons, "High violation count")
	assert.Contains(t, reasons, "Inconsistent user agent")
	assert.Contains(t, reasons, "Unusual geographic location")
}