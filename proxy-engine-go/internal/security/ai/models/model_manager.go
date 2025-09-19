package models

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/sirupsen/logrus"
)

// DefaultModelManager implements the ModelManager interface
type DefaultModelManager struct {
	storage     ai.AIStorage
	models      map[string]map[string]ai.MLModel // name -> version -> model
	activeModel map[string]string                // name -> active version
	logger      *logrus.Logger
	mu          sync.RWMutex
}

// NewDefaultModelManager creates a new model manager
func NewDefaultModelManager(storage ai.AIStorage, logger *logrus.Logger) *DefaultModelManager {
	return &DefaultModelManager{
		storage:     storage,
		models:      make(map[string]map[string]ai.MLModel),
		activeModel: make(map[string]string),
		logger:      logger,
	}
}

// LoadModel loads a model by name and version
func (mm *DefaultModelManager) LoadModel(ctx context.Context, name, version string) (ai.MLModel, error) {
	mm.mu.RLock()
	if versions, exists := mm.models[name]; exists {
		if model, exists := versions[version]; exists {
			mm.mu.RUnlock()
			return model, nil
		}
	}
	mm.mu.RUnlock()
	
	// Try to load from storage
	data, err := mm.storage.LoadModel(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("failed to load model %s:%s from storage: %w", name, version, err)
	}
	
	// Create appropriate model based on type
	model, err := mm.createModelFromData(name, version, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create model from data: %w", err)
	}
	
	// Cache the model
	mm.mu.Lock()
	if _, exists := mm.models[name]; !exists {
		mm.models[name] = make(map[string]ai.MLModel)
	}
	mm.models[name][version] = model
	mm.mu.Unlock()
	
	mm.logger.Infof("Loaded model %s version %s", name, version)
	return model, nil
}

// SaveModel saves a model with version
func (mm *DefaultModelManager) SaveModel(ctx context.Context, name, version string, model ai.MLModel) error {
	// Export model data
	data, err := model.Export(ctx)
	if err != nil {
		return fmt.Errorf("failed to export model: %w", err)
	}
	
	// Save to storage
	if err := mm.storage.SaveModel(ctx, name, version, data); err != nil {
		return fmt.Errorf("failed to save model to storage: %w", err)
	}
	
	// Cache the model
	mm.mu.Lock()
	if _, exists := mm.models[name]; !exists {
		mm.models[name] = make(map[string]ai.MLModel)
	}
	mm.models[name][version] = model
	mm.mu.Unlock()
	
	mm.logger.Infof("Saved model %s version %s", name, version)
	return nil
}

// ListModels returns available models
func (mm *DefaultModelManager) ListModels(ctx context.Context) ([]*ai.ModelInfo, error) {
	// Get models from storage
	storageModels, err := mm.storage.ListModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list models from storage: %w", err)
	}
	
	// Merge with cached models
	modelMap := make(map[string]*ai.ModelInfo)
	
	// Add storage models
	for _, model := range storageModels {
		key := fmt.Sprintf("%s:%s", model.Name, model.Version)
		modelMap[key] = model
	}
	
	// Add cached models (may have more recent info)
	mm.mu.RLock()
	for name, versions := range mm.models {
		for version, model := range versions {
			key := fmt.Sprintf("%s:%s", name, version)
			info := &ai.ModelInfo{
				Name:      name,
				Version:   version,
				IsActive:  mm.activeModel[name] == version,
			}
			
			// Get additional info from model if available
			if metrics, err := model.GetMetrics(ctx); err == nil {
				info.Metrics = metrics
			}
			
			modelMap[key] = info
		}
	}
	mm.mu.RUnlock()
	
	// Convert to slice and sort
	var models []*ai.ModelInfo
	for _, model := range modelMap {
		models = append(models, model)
	}
	
	sort.Slice(models, func(i, j int) bool {
		if models[i].Name != models[j].Name {
			return models[i].Name < models[j].Name
		}
		return mm.compareVersions(models[i].Version, models[j].Version) > 0
	})
	
	return models, nil
}

// GetLatestVersion returns the latest version of a model
func (mm *DefaultModelManager) GetLatestVersion(ctx context.Context, name string) (string, error) {
	models, err := mm.ListModels(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list models: %w", err)
	}
	
	var latestVersion string
	for _, model := range models {
		if model.Name == name {
			if latestVersion == "" || mm.compareVersions(model.Version, latestVersion) > 0 {
				latestVersion = model.Version
			}
		}
	}
	
	if latestVersion == "" {
		return "", fmt.Errorf("no versions found for model %s", name)
	}
	
	return latestVersion, nil
}

// DeleteModel deletes a model version
func (mm *DefaultModelManager) DeleteModel(ctx context.Context, name, version string) error {
	// Delete from storage
	if err := mm.storage.DeleteModel(ctx, name, version); err != nil {
		return fmt.Errorf("failed to delete model from storage: %w", err)
	}
	
	// Remove from cache
	mm.mu.Lock()
	if versions, exists := mm.models[name]; exists {
		delete(versions, version)
		if len(versions) == 0 {
			delete(mm.models, name)
		}
	}
	
	// Clear active model if this was the active version
	if mm.activeModel[name] == version {
		delete(mm.activeModel, name)
	}
	mm.mu.Unlock()
	
	mm.logger.Infof("Deleted model %s version %s", name, version)
	return nil
}

// SetActiveModel sets the active version for a model
func (mm *DefaultModelManager) SetActiveModel(ctx context.Context, name, version string) error {
	// Verify model exists
	_, err := mm.LoadModel(ctx, name, version)
	if err != nil {
		return fmt.Errorf("cannot set active model - model not found: %w", err)
	}
	
	mm.mu.Lock()
	mm.activeModel[name] = version
	mm.mu.Unlock()
	
	mm.logger.Infof("Set active model %s to version %s", name, version)
	return nil
}

// GetActiveModel returns the active model for a given name
func (mm *DefaultModelManager) GetActiveModel(ctx context.Context, name string) (ai.MLModel, error) {
	mm.mu.RLock()
	activeVersion, exists := mm.activeModel[name]
	mm.mu.RUnlock()
	
	if !exists {
		// Try to get latest version as active
		latestVersion, err := mm.GetLatestVersion(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("no active model set for %s and cannot determine latest: %w", name, err)
		}
		
		// Set as active
		if err := mm.SetActiveModel(ctx, name, latestVersion); err != nil {
			return nil, fmt.Errorf("failed to set latest version as active: %w", err)
		}
		
		activeVersion = latestVersion
	}
	
	return mm.LoadModel(ctx, name, activeVersion)
}

// GetModelStats returns statistics about managed models
func (mm *DefaultModelManager) GetModelStats(ctx context.Context) (map[string]interface{}, error) {
	models, err := mm.ListModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get model stats: %w", err)
	}
	
	stats := map[string]interface{}{
		"total_models":    len(models),
		"models_by_name":  make(map[string]int),
		"active_models":   len(mm.activeModel),
		"cached_models":   0,
		"last_updated":    time.Now(),
	}
	
	modelsByName := stats["models_by_name"].(map[string]int)
	
	mm.mu.RLock()
	for name, versions := range mm.models {
		modelsByName[name] = len(versions)
		stats["cached_models"] = stats["cached_models"].(int) + len(versions)
	}
	mm.mu.RUnlock()
	
	return stats, nil
}

// CleanupOldVersions removes old model versions, keeping only the specified number of recent versions
func (mm *DefaultModelManager) CleanupOldVersions(ctx context.Context, name string, keepVersions int) error {
	if keepVersions <= 0 {
		return fmt.Errorf("keepVersions must be positive")
	}
	
	models, err := mm.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("failed to list models for cleanup: %w", err)
	}
	
	// Filter models by name and sort by version
	var modelVersions []*ai.ModelInfo
	for _, model := range models {
		if model.Name == name {
			modelVersions = append(modelVersions, model)
		}
	}
	
	if len(modelVersions) <= keepVersions {
		return nil // Nothing to cleanup
	}
	
	// Sort by version (newest first)
	sort.Slice(modelVersions, func(i, j int) bool {
		return mm.compareVersions(modelVersions[i].Version, modelVersions[j].Version) > 0
	})
	
	// Delete old versions
	deleted := 0
	for i := keepVersions; i < len(modelVersions); i++ {
		version := modelVersions[i].Version
		
		// Don't delete active version
		mm.mu.RLock()
		isActive := mm.activeModel[name] == version
		mm.mu.RUnlock()
		
		if !isActive {
			if err := mm.DeleteModel(ctx, name, version); err != nil {
				mm.logger.Warnf("Failed to delete old model version %s:%s: %v", name, version, err)
			} else {
				deleted++
			}
		}
	}
	
	mm.logger.Infof("Cleaned up %d old versions of model %s", deleted, name)
	return nil
}

// createModelFromData creates a model instance from stored data
func (mm *DefaultModelManager) createModelFromData(name, version string, data []byte) (ai.MLModel, error) {
	// For now, create a base model and import the data
	// In a real implementation, this would create specific model types based on metadata
	baseModel := NewBaseModel(name, version, "base", "Imported model", mm.logger)
	
	if err := baseModel.Import(context.Background(), data); err != nil {
		return nil, fmt.Errorf("failed to import model data: %w", err)
	}
	
	baseModel.SetReady(true)
	return baseModel, nil
}

// compareVersions compares two version strings
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2
func (mm *DefaultModelManager) compareVersions(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}
	
	// Simple semantic version comparison
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		
		if i < len(parts1) {
			if num, err := strconv.Atoi(parts1[i]); err == nil {
				p1 = num
			}
		}
		
		if i < len(parts2) {
			if num, err := strconv.Atoi(parts2[i]); err == nil {
				p2 = num
			}
		}
		
		if p1 > p2 {
			return 1
		} else if p1 < p2 {
			return -1
		}
	}
	
	return 0
}