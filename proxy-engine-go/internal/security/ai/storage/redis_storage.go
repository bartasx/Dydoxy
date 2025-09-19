package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"
)

// RedisAIStorage implements AIStorage interface using Redis
type RedisAIStorage struct {
	client *redis.Client
	logger *logrus.Logger
	prefix string
}

// NewRedisAIStorage creates a new Redis-based AI storage
func NewRedisAIStorage(client *redis.Client, logger *logrus.Logger) *RedisAIStorage {
	return &RedisAIStorage{
		client: client,
		logger: logger,
		prefix: "ai:",
	}
}

// Model storage methods

// SaveModel saves a model to Redis
func (r *RedisAIStorage) SaveModel(ctx context.Context, name, version string, data []byte) error {
	key := r.modelKey(name, version)
	
	// Save model data
	if err := r.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save model data: %w", err)
	}
	
	// Update model metadata
	metadata := map[string]interface{}{
		"name":       name,
		"version":    version,
		"size":       len(data),
		"created_at": time.Now().Unix(),
		"updated_at": time.Now().Unix(),
	}
	
	metadataKey := r.modelMetadataKey(name, version)
	if err := r.client.HMSet(ctx, metadataKey, metadata).Err(); err != nil {
		return fmt.Errorf("failed to save model metadata: %w", err)
	}
	
	// Add to model list
	listKey := r.modelListKey()
	modelID := fmt.Sprintf("%s:%s", name, version)
	if err := r.client.SAdd(ctx, listKey, modelID).Err(); err != nil {
		return fmt.Errorf("failed to add model to list: %w", err)
	}
	
	r.logger.Infof("Saved model %s version %s to Redis", name, version)
	return nil
}

// LoadModel loads a model from Redis
func (r *RedisAIStorage) LoadModel(ctx context.Context, name, version string) ([]byte, error) {
	key := r.modelKey(name, version)
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("model %s:%s not found", name, version)
		}
		return nil, fmt.Errorf("failed to load model: %w", err)
	}
	
	return data, nil
}

// ListModels lists all available models
func (r *RedisAIStorage) ListModels(ctx context.Context) ([]*ai.ModelInfo, error) {
	listKey := r.modelListKey()
	
	modelIDs, err := r.client.SMembers(ctx, listKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get model list: %w", err)
	}
	
	var models []*ai.ModelInfo
	for _, modelID := range modelIDs {
		parts := strings.Split(modelID, ":")
		if len(parts) != 2 {
			r.logger.Warnf("Invalid model ID format: %s", modelID)
			continue
		}
		
		name, version := parts[0], parts[1]
		metadataKey := r.modelMetadataKey(name, version)
		
		metadata, err := r.client.HGetAll(ctx, metadataKey).Result()
		if err != nil {
			r.logger.Warnf("Failed to get metadata for model %s: %v", modelID, err)
			continue
		}
		
		model := &ai.ModelInfo{
			Name:    name,
			Version: version,
		}
		
		if sizeStr, exists := metadata["size"]; exists {
			if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
				model.Size = size
			}
		}
		
		if createdAtStr, exists := metadata["created_at"]; exists {
			if createdAt, err := strconv.ParseInt(createdAtStr, 10, 64); err == nil {
				model.CreatedAt = time.Unix(createdAt, 0)
			}
		}
		
		if updatedAtStr, exists := metadata["updated_at"]; exists {
			if updatedAt, err := strconv.ParseInt(updatedAtStr, 10, 64); err == nil {
				model.UpdatedAt = time.Unix(updatedAt, 0)
			}
		}
		
		models = append(models, model)
	}
	
	return models, nil
}

// DeleteModel deletes a model from Redis
func (r *RedisAIStorage) DeleteModel(ctx context.Context, name, version string) error {
	key := r.modelKey(name, version)
	metadataKey := r.modelMetadataKey(name, version)
	listKey := r.modelListKey()
	modelID := fmt.Sprintf("%s:%s", name, version)
	
	// Delete model data
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete model data: %w", err)
	}
	
	// Delete metadata
	if err := r.client.Del(ctx, metadataKey).Err(); err != nil {
		return fmt.Errorf("failed to delete model metadata: %w", err)
	}
	
	// Remove from list
	if err := r.client.SRem(ctx, listKey, modelID).Err(); err != nil {
		return fmt.Errorf("failed to remove model from list: %w", err)
	}
	
	r.logger.Infof("Deleted model %s version %s from Redis", name, version)
	return nil
}

// Training data storage methods

// SaveTrainingExample saves a training example
func (r *RedisAIStorage) SaveTrainingExample(ctx context.Context, example *ai.TrainingExample) error {
	key := r.trainingExampleKey(example.ID)
	
	data, err := json.Marshal(example)
	if err != nil {
		return fmt.Errorf("failed to marshal training example: %w", err)
	}
	
	if err := r.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save training example: %w", err)
	}
	
	// Add to training examples list with timestamp for ordering
	listKey := r.trainingExamplesListKey()
	score := float64(example.Timestamp.Unix())
	if err := r.client.ZAdd(ctx, listKey, redis.Z{Score: score, Member: example.ID}).Err(); err != nil {
		return fmt.Errorf("failed to add training example to list: %w", err)
	}
	
	return nil
}

// LoadTrainingExamples loads training examples with pagination
func (r *RedisAIStorage) LoadTrainingExamples(ctx context.Context, limit int, offset int) ([]*ai.TrainingExample, error) {
	listKey := r.trainingExamplesListKey()
	
	// Get IDs from sorted set (newest first)
	ids, err := r.client.ZRevRange(ctx, listKey, int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get training example IDs: %w", err)
	}
	
	var examples []*ai.TrainingExample
	for _, id := range ids {
		key := r.trainingExampleKey(id)
		data, err := r.client.Get(ctx, key).Bytes()
		if err != nil {
			if err == redis.Nil {
				r.logger.Warnf("Training example %s not found", id)
				continue
			}
			return nil, fmt.Errorf("failed to load training example %s: %w", id, err)
		}
		
		var example ai.TrainingExample
		if err := json.Unmarshal(data, &example); err != nil {
			r.logger.Warnf("Failed to unmarshal training example %s: %v", id, err)
			continue
		}
		
		examples = append(examples, &example)
	}
	
	return examples, nil
}

// Behavioral profiles storage methods

// SaveBehaviorProfile saves a behavioral profile
func (r *RedisAIStorage) SaveBehaviorProfile(ctx context.Context, subject string, profile *ai.BehaviorProfile) error {
	key := r.behaviorProfileKey(subject)
	
	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal behavior profile: %w", err)
	}
	
	// Set with TTL (profiles expire after 30 days of inactivity)
	ttl := 30 * 24 * time.Hour
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to save behavior profile: %w", err)
	}
	
	return nil
}

// LoadBehaviorProfile loads a behavioral profile
func (r *RedisAIStorage) LoadBehaviorProfile(ctx context.Context, subject string) (*ai.BehaviorProfile, error) {
	key := r.behaviorProfileKey(subject)
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("behavior profile for %s not found", subject)
		}
		return nil, fmt.Errorf("failed to load behavior profile: %w", err)
	}
	
	var profile ai.BehaviorProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal behavior profile: %w", err)
	}
	
	return &profile, nil
}

// Threat analysis results storage methods

// SaveThreatAnalysis saves a threat analysis result
func (r *RedisAIStorage) SaveThreatAnalysis(ctx context.Context, result *ai.ThreatAnalysisResult) error {
	key := r.threatAnalysisKey(result.RequestID)
	
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal threat analysis: %w", err)
	}
	
	// Set with TTL (results expire after 7 days)
	ttl := 7 * 24 * time.Hour
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to save threat analysis: %w", err)
	}
	
	// Add to recent analyses list for monitoring
	listKey := r.recentAnalysesKey()
	score := float64(result.Timestamp.Unix())
	if err := r.client.ZAdd(ctx, listKey, redis.Z{Score: score, Member: result.RequestID}).Err(); err != nil {
		r.logger.Warnf("Failed to add analysis to recent list: %v", err)
	}
	
	// Keep only last 10000 entries in recent analyses
	if err := r.client.ZRemRangeByRank(ctx, listKey, 0, -10001).Err(); err != nil {
		r.logger.Warnf("Failed to trim recent analyses list: %v", err)
	}
	
	return nil
}

// LoadThreatAnalysis loads a threat analysis result
func (r *RedisAIStorage) LoadThreatAnalysis(ctx context.Context, requestID string) (*ai.ThreatAnalysisResult, error) {
	key := r.threatAnalysisKey(requestID)
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("threat analysis for request %s not found", requestID)
		}
		return nil, fmt.Errorf("failed to load threat analysis: %w", err)
	}
	
	var result ai.ThreatAnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal threat analysis: %w", err)
	}
	
	return &result, nil
}

// Statistics storage methods

// SaveAIStats saves AI threat detection statistics
func (r *RedisAIStorage) SaveAIStats(ctx context.Context, stats *ai.AIThreatStats) error {
	key := r.aiStatsKey()
	
	data, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal AI stats: %w", err)
	}
	
	if err := r.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save AI stats: %w", err)
	}
	
	return nil
}

// LoadAIStats loads AI threat detection statistics
func (r *RedisAIStorage) LoadAIStats(ctx context.Context) (*ai.AIThreatStats, error) {
	key := r.aiStatsKey()
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			// Return empty stats if none exist
			return &ai.AIThreatStats{
				ThreatsByType:  make(map[ai.ThreatType]int64),
				ThreatsByLevel: make(map[ai.ThreatLevel]int64),
				ActionsTaken:   make(map[ai.ActionType]int64),
				ModelAccuracy:  make(map[string]float64),
				LastUpdated:    time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("failed to load AI stats: %w", err)
	}
	
	var stats ai.AIThreatStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AI stats: %w", err)
	}
	
	return &stats, nil
}

// Configuration storage methods

// SaveThreatPolicies saves threat detection policies
func (r *RedisAIStorage) SaveThreatPolicies(ctx context.Context, policies *ai.ThreatPolicies) error {
	key := r.threatPoliciesKey()
	
	data, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("failed to marshal threat policies: %w", err)
	}
	
	if err := r.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save threat policies: %w", err)
	}
	
	return nil
}

// LoadThreatPolicies loads threat detection policies
func (r *RedisAIStorage) LoadThreatPolicies(ctx context.Context) (*ai.ThreatPolicies, error) {
	key := r.threatPoliciesKey()
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			// Return default policies if none exist
			return &ai.ThreatPolicies{
				GlobalEnabled:        true,
				ConfidenceThreshold:  0.8,
				ThreatLevelThresholds: map[ai.ThreatLevel]float64{
					ai.ThreatLevelLow:      0.3,
					ai.ThreatLevelMedium:   0.6,
					ai.ThreatLevelHigh:     0.8,
					ai.ThreatLevelCritical: 0.95,
				},
				ActionPolicies: map[ai.ThreatType]ai.ActionType{
					ai.ThreatTypeMalware:  ai.ActionBlock,
					ai.ThreatTypePhishing: ai.ActionBlock,
					ai.ThreatTypeBotnet:   ai.ActionBlock,
				},
				BehavioralAnalysis: true,
				MachineLearning:    true,
				ThreatIntelligence: true,
				AlertingEnabled:    true,
				AlertThreshold:     ai.ThreatLevelMedium,
				UpdatedAt:          time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("failed to load threat policies: %w", err)
	}
	
	var policies ai.ThreatPolicies
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal threat policies: %w", err)
	}
	
	return &policies, nil
}

// Key generation methods

func (r *RedisAIStorage) modelKey(name, version string) string {
	return fmt.Sprintf("%smodel:%s:%s", r.prefix, name, version)
}

func (r *RedisAIStorage) modelMetadataKey(name, version string) string {
	return fmt.Sprintf("%smodel:meta:%s:%s", r.prefix, name, version)
}

func (r *RedisAIStorage) modelListKey() string {
	return fmt.Sprintf("%smodels", r.prefix)
}

func (r *RedisAIStorage) trainingExampleKey(id string) string {
	return fmt.Sprintf("%straining:%s", r.prefix, id)
}

func (r *RedisAIStorage) trainingExamplesListKey() string {
	return fmt.Sprintf("%straining:list", r.prefix)
}

func (r *RedisAIStorage) behaviorProfileKey(subject string) string {
	return fmt.Sprintf("%sbehavior:%s", r.prefix, subject)
}

func (r *RedisAIStorage) threatAnalysisKey(requestID string) string {
	return fmt.Sprintf("%sanalysis:%s", r.prefix, requestID)
}

func (r *RedisAIStorage) recentAnalysesKey() string {
	return fmt.Sprintf("%sanalysis:recent", r.prefix)
}

func (r *RedisAIStorage) aiStatsKey() string {
	return fmt.Sprintf("%sstats", r.prefix)
}

func (r *RedisAIStorage) threatPoliciesKey() string {
	return fmt.Sprintf("%spolicies", r.prefix)
}

// Utility methods

// GetRecentThreatAnalyses returns recent threat analyses for monitoring
func (r *RedisAIStorage) GetRecentThreatAnalyses(ctx context.Context, limit int) ([]*ai.ThreatAnalysisResult, error) {
	listKey := r.recentAnalysesKey()
	
	// Get recent request IDs
	ids, err := r.client.ZRevRange(ctx, listKey, 0, int64(limit-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get recent analysis IDs: %w", err)
	}
	
	var analyses []*ai.ThreatAnalysisResult
	for _, id := range ids {
		if analysis, err := r.LoadThreatAnalysis(ctx, id); err == nil {
			analyses = append(analyses, analysis)
		}
	}
	
	return analyses, nil
}

// CleanupExpiredData removes expired data from Redis
func (r *RedisAIStorage) CleanupExpiredData(ctx context.Context) error {
	// Redis handles TTL automatically, but we can clean up sorted sets
	listKey := r.recentAnalysesKey()
	
	// Remove entries older than 7 days
	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()
	removed, err := r.client.ZRemRangeByScore(ctx, listKey, "0", fmt.Sprintf("%d", cutoff)).Result()
	if err != nil {
		return fmt.Errorf("failed to cleanup recent analyses: %w", err)
	}
	
	if removed > 0 {
		r.logger.Infof("Cleaned up %d expired analysis entries", removed)
	}
	
	return nil
}