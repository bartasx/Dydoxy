package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) *redis.Client {
	// Use Redis database 15 for testing to avoid conflicts
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15,
	})
	
	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available for testing")
	}
	
	// Clean up test database
	client.FlushDB(ctx)
	
	return client
}

func TestRedisAIStorage_ModelOperations(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Test saving a model
	modelData := []byte("test model data")
	err := storage.SaveModel(ctx, "test-model", "1.0.0", modelData)
	require.NoError(t, err)
	
	// Test loading the model
	loadedData, err := storage.LoadModel(ctx, "test-model", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, modelData, loadedData)
	
	// Test listing models
	models, err := storage.ListModels(ctx)
	require.NoError(t, err)
	assert.Len(t, models, 1)
	assert.Equal(t, "test-model", models[0].Name)
	assert.Equal(t, "1.0.0", models[0].Version)
	assert.Equal(t, int64(len(modelData)), models[0].Size)
	
	// Test saving another version
	modelData2 := []byte("test model data v2")
	err = storage.SaveModel(ctx, "test-model", "2.0.0", modelData2)
	require.NoError(t, err)
	
	// Test listing multiple versions
	models, err = storage.ListModels(ctx)
	require.NoError(t, err)
	assert.Len(t, models, 2)
	
	// Test deleting a model
	err = storage.DeleteModel(ctx, "test-model", "1.0.0")
	require.NoError(t, err)
	
	// Verify deletion
	_, err = storage.LoadModel(ctx, "test-model", "1.0.0")
	assert.Error(t, err)
	
	models, err = storage.ListModels(ctx)
	require.NoError(t, err)
	assert.Len(t, models, 1)
	assert.Equal(t, "2.0.0", models[0].Version)
}

func TestRedisAIStorage_TrainingExamples(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Create test training examples
	examples := []*ai.TrainingExample{
		{
			ID:       "example-1",
			Features: map[string]float64{"feature1": 1.0, "feature2": 0.5},
			Label:    true,
			Source:   "manual",
			Timestamp: time.Now().Add(-2 * time.Hour),
		},
		{
			ID:       "example-2",
			Features: map[string]float64{"feature1": 0.3, "feature2": 0.8},
			Label:    false,
			Source:   "automated",
			Timestamp: time.Now().Add(-1 * time.Hour),
		},
		{
			ID:       "example-3",
			Features: map[string]float64{"feature1": 0.7, "feature2": 0.2},
			Label:    true,
			Source:   "feedback",
			Timestamp: time.Now(),
		},
	}
	
	// Save training examples
	for _, example := range examples {
		err := storage.SaveTrainingExample(ctx, example)
		require.NoError(t, err)
	}
	
	// Load training examples (should be in reverse chronological order)
	loadedExamples, err := storage.LoadTrainingExamples(ctx, 10, 0)
	require.NoError(t, err)
	assert.Len(t, loadedExamples, 3)
	
	// Verify order (newest first)
	assert.Equal(t, "example-3", loadedExamples[0].ID)
	assert.Equal(t, "example-2", loadedExamples[1].ID)
	assert.Equal(t, "example-1", loadedExamples[2].ID)
	
	// Test pagination
	loadedExamples, err = storage.LoadTrainingExamples(ctx, 2, 0)
	require.NoError(t, err)
	assert.Len(t, loadedExamples, 2)
	
	loadedExamples, err = storage.LoadTrainingExamples(ctx, 2, 2)
	require.NoError(t, err)
	assert.Len(t, loadedExamples, 1)
	assert.Equal(t, "example-1", loadedExamples[0].ID)
}

func TestRedisAIStorage_BehaviorProfiles(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Create test behavior profile
	profile := &ai.BehaviorProfile{
		Subject:          "user123",
		FirstSeen:        time.Now().Add(-24 * time.Hour),
		LastSeen:         time.Now(),
		RequestCount:     150,
		AverageFrequency: 2.5,
		CommonUserAgents: []string{"Mozilla/5.0", "Chrome/91.0"},
		CommonPaths:      []string{"/api/users", "/dashboard"},
		TimePatterns:     map[int]int64{9: 20, 10: 25, 14: 30},
		GeoLocations:     []string{"US", "CA"},
		TrustScore:       85.5,
		ViolationCount:   2,
		UpdatedAt:        time.Now(),
	}
	
	// Save behavior profile
	err := storage.SaveBehaviorProfile(ctx, profile.Subject, profile)
	require.NoError(t, err)
	
	// Load behavior profile
	loadedProfile, err := storage.LoadBehaviorProfile(ctx, profile.Subject)
	require.NoError(t, err)
	
	assert.Equal(t, profile.Subject, loadedProfile.Subject)
	assert.Equal(t, profile.RequestCount, loadedProfile.RequestCount)
	assert.Equal(t, profile.AverageFrequency, loadedProfile.AverageFrequency)
	assert.Equal(t, profile.TrustScore, loadedProfile.TrustScore)
	assert.Equal(t, profile.ViolationCount, loadedProfile.ViolationCount)
	assert.Equal(t, len(profile.CommonUserAgents), len(loadedProfile.CommonUserAgents))
	assert.Equal(t, len(profile.TimePatterns), len(loadedProfile.TimePatterns))
	
	// Test loading non-existent profile
	_, err = storage.LoadBehaviorProfile(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestRedisAIStorage_ThreatAnalysis(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Create test threat analysis result
	result := &ai.ThreatAnalysisResult{
		RequestID:        "req-123",
		IsThreat:         true,
		ThreatType:       ai.ThreatTypeMalware,
		ThreatLevel:      ai.ThreatLevelHigh,
		Confidence:       0.92,
		RecommendedAction: ai.ActionBlock,
		Reason:           "Malicious URL detected",
		ProcessingTime:   25 * time.Millisecond,
		Timestamp:        time.Now(),
	}
	
	// Save threat analysis
	err := storage.SaveThreatAnalysis(ctx, result)
	require.NoError(t, err)
	
	// Load threat analysis
	loadedResult, err := storage.LoadThreatAnalysis(ctx, result.RequestID)
	require.NoError(t, err)
	
	assert.Equal(t, result.RequestID, loadedResult.RequestID)
	assert.Equal(t, result.IsThreat, loadedResult.IsThreat)
	assert.Equal(t, result.ThreatType, loadedResult.ThreatType)
	assert.Equal(t, result.ThreatLevel, loadedResult.ThreatLevel)
	assert.Equal(t, result.Confidence, loadedResult.Confidence)
	assert.Equal(t, result.RecommendedAction, loadedResult.RecommendedAction)
	assert.Equal(t, result.Reason, loadedResult.Reason)
	
	// Test loading non-existent analysis
	_, err = storage.LoadThreatAnalysis(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestRedisAIStorage_AIStats(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Test loading default stats (should not error)
	stats, err := storage.LoadAIStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.NotNil(t, stats.ThreatsByType)
	assert.NotNil(t, stats.ThreatsByLevel)
	assert.NotNil(t, stats.ActionsTaken)
	assert.NotNil(t, stats.ModelAccuracy)
	
	// Create test stats
	testStats := &ai.AIThreatStats{
		TotalRequests:     1000,
		ThreatsDetected:   50,
		BlockedRequests:   45,
		ChallengedRequests: 5,
		ThreatsByType: map[ai.ThreatType]int64{
			ai.ThreatTypeMalware:  20,
			ai.ThreatTypePhishing: 15,
			ai.ThreatTypeBotnet:   10,
		},
		ThreatsByLevel: map[ai.ThreatLevel]int64{
			ai.ThreatLevelLow:      10,
			ai.ThreatLevelMedium:   20,
			ai.ThreatLevelHigh:     15,
			ai.ThreatLevelCritical: 5,
		},
		ActionsTaken: map[ai.ActionType]int64{
			ai.ActionBlock:     45,
			ai.ActionChallenge: 5,
		},
		AverageConfidence:     0.85,
		AverageProcessingTime: 30 * time.Millisecond,
		ModelAccuracy: map[string]float64{
			"content-model":    0.92,
			"behavioral-model": 0.88,
		},
		LastUpdated: time.Now(),
	}
	
	// Save stats
	err = storage.SaveAIStats(ctx, testStats)
	require.NoError(t, err)
	
	// Load stats
	loadedStats, err := storage.LoadAIStats(ctx)
	require.NoError(t, err)
	
	assert.Equal(t, testStats.TotalRequests, loadedStats.TotalRequests)
	assert.Equal(t, testStats.ThreatsDetected, loadedStats.ThreatsDetected)
	assert.Equal(t, testStats.BlockedRequests, loadedStats.BlockedRequests)
	assert.Equal(t, testStats.AverageConfidence, loadedStats.AverageConfidence)
	assert.Equal(t, len(testStats.ThreatsByType), len(loadedStats.ThreatsByType))
	assert.Equal(t, len(testStats.ModelAccuracy), len(loadedStats.ModelAccuracy))
}

func TestRedisAIStorage_ThreatPolicies(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Test loading default policies (should not error)
	policies, err := storage.LoadThreatPolicies(ctx)
	require.NoError(t, err)
	assert.NotNil(t, policies)
	assert.True(t, policies.GlobalEnabled)
	assert.Equal(t, 0.8, policies.ConfidenceThreshold)
	assert.NotNil(t, policies.ThreatLevelThresholds)
	assert.NotNil(t, policies.ActionPolicies)
	
	// Create test policies
	testPolicies := &ai.ThreatPolicies{
		GlobalEnabled:       true,
		ConfidenceThreshold: 0.9,
		ThreatLevelThresholds: map[ai.ThreatLevel]float64{
			ai.ThreatLevelLow:      0.4,
			ai.ThreatLevelMedium:   0.7,
			ai.ThreatLevelHigh:     0.9,
			ai.ThreatLevelCritical: 0.98,
		},
		ActionPolicies: map[ai.ThreatType]ai.ActionType{
			ai.ThreatTypeMalware:    ai.ActionBlock,
			ai.ThreatTypePhishing:   ai.ActionBlock,
			ai.ThreatTypeSuspicious: ai.ActionChallenge,
		},
		BehavioralAnalysis: true,
		MachineLearning:    true,
		ThreatIntelligence: true,
		AlertingEnabled:    true,
		AlertThreshold:     ai.ThreatLevelHigh,
		UpdatedAt:          time.Now(),
	}
	
	// Save policies
	err = storage.SaveThreatPolicies(ctx, testPolicies)
	require.NoError(t, err)
	
	// Load policies
	loadedPolicies, err := storage.LoadThreatPolicies(ctx)
	require.NoError(t, err)
	
	assert.Equal(t, testPolicies.GlobalEnabled, loadedPolicies.GlobalEnabled)
	assert.Equal(t, testPolicies.ConfidenceThreshold, loadedPolicies.ConfidenceThreshold)
	assert.Equal(t, testPolicies.BehavioralAnalysis, loadedPolicies.BehavioralAnalysis)
	assert.Equal(t, testPolicies.MachineLearning, loadedPolicies.MachineLearning)
	assert.Equal(t, testPolicies.AlertThreshold, loadedPolicies.AlertThreshold)
	assert.Equal(t, len(testPolicies.ThreatLevelThresholds), len(loadedPolicies.ThreatLevelThresholds))
	assert.Equal(t, len(testPolicies.ActionPolicies), len(loadedPolicies.ActionPolicies))
}

func TestRedisAIStorage_RecentAnalyses(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Create multiple threat analyses
	analyses := []*ai.ThreatAnalysisResult{
		{
			RequestID: "req-1",
			IsThreat:  true,
			Timestamp: time.Now().Add(-3 * time.Hour),
		},
		{
			RequestID: "req-2",
			IsThreat:  false,
			Timestamp: time.Now().Add(-2 * time.Hour),
		},
		{
			RequestID: "req-3",
			IsThreat:  true,
			Timestamp: time.Now().Add(-1 * time.Hour),
		},
	}
	
	// Save analyses
	for _, analysis := range analyses {
		err := storage.SaveThreatAnalysis(ctx, analysis)
		require.NoError(t, err)
	}
	
	// Get recent analyses
	recentAnalyses, err := storage.GetRecentThreatAnalyses(ctx, 5)
	require.NoError(t, err)
	assert.Len(t, recentAnalyses, 3)
	
	// Should be in reverse chronological order
	assert.Equal(t, "req-3", recentAnalyses[0].RequestID)
	assert.Equal(t, "req-2", recentAnalyses[1].RequestID)
	assert.Equal(t, "req-1", recentAnalyses[2].RequestID)
	
	// Test limit
	recentAnalyses, err = storage.GetRecentThreatAnalyses(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, recentAnalyses, 2)
}

func TestRedisAIStorage_CleanupExpiredData(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := NewRedisAIStorage(client, logger)
	ctx := context.Background()
	
	// Create old analysis (8 days ago)
	oldAnalysis := &ai.ThreatAnalysisResult{
		RequestID: "old-req",
		IsThreat:  true,
		Timestamp: time.Now().Add(-8 * 24 * time.Hour),
	}
	
	// Manually add to recent list with old timestamp
	listKey := storage.recentAnalysesKey()
	score := float64(oldAnalysis.Timestamp.Unix())
	err := client.ZAdd(ctx, listKey, redis.Z{Score: score, Member: oldAnalysis.RequestID}).Err()
	require.NoError(t, err)
	
	// Add recent analysis
	recentAnalysis := &ai.ThreatAnalysisResult{
		RequestID: "recent-req",
		IsThreat:  true,
		Timestamp: time.Now(),
	}
	err = storage.SaveThreatAnalysis(ctx, recentAnalysis)
	require.NoError(t, err)
	
	// Verify both entries exist
	count, err := client.ZCard(ctx, listKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
	
	// Run cleanup
	err = storage.CleanupExpiredData(ctx)
	require.NoError(t, err)
	
	// Verify old entry was removed
	count, err = client.ZCard(ctx, listKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	
	// Verify recent entry still exists
	members, err := client.ZMembers(ctx, listKey).Result()
	require.NoError(t, err)
	assert.Contains(t, members, "recent-req")
	assert.NotContains(t, members, "old-req")
}