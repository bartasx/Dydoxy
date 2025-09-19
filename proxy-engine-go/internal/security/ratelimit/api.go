package ratelimit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RateLimitAPI provides REST API endpoints for rate limiting management
type RateLimitAPI struct {
	manager *TokenBucketManager
	limiter *MultiLayerRateLimiter
	storage BucketStorage
	logger  *logrus.Logger
}

// NewRateLimitAPI creates a new rate limiting API
func NewRateLimitAPI(manager *TokenBucketManager, limiter *MultiLayerRateLimiter, storage BucketStorage, logger *logrus.Logger) *RateLimitAPI {
	return &RateLimitAPI{
		manager: manager,
		limiter: limiter,
		storage: storage,
		logger:  logger,
	}
}

// RegisterRoutes registers API routes with Gin router
func (api *RateLimitAPI) RegisterRoutes(r *gin.RouterGroup) {
	// Configuration management
	r.GET("/configs", api.GetConfigs)
	r.POST("/configs", api.CreateConfig)
	r.GET("/configs/:name", api.GetConfig)
	r.PUT("/configs/:name", api.UpdateConfig)
	r.DELETE("/configs/:name", api.DeleteConfig)
	
	// Bucket management
	r.GET("/buckets", api.GetBuckets)
	r.GET("/buckets/:key", api.GetBucket)
	r.POST("/buckets/:key/reset", api.ResetBucket)
	r.DELETE("/buckets/:key", api.DeleteBucket)
	
	// Rate limit checking
	r.POST("/check", api.CheckRateLimit)
	r.POST("/check/multi", api.CheckMultiLayerRateLimit)
	
	// Statistics and monitoring
	r.GET("/stats", api.GetStats)
	r.POST("/cleanup", api.CleanupExpired)
	
	// Testing and debugging
	r.POST("/test", api.TestRateLimit)
}

// CreateConfigRequest represents a request to create a new configuration
type CreateConfigRequest struct {
	Name          string `json:"name" binding:"required"`
	Capacity      int64  `json:"capacity" binding:"required,min=1"`
	RefillRate    int64  `json:"refill_rate" binding:"required,min=1"`
	InitialTokens int64  `json:"initial_tokens,omitempty"`
}

// UpdateConfigRequest represents a request to update a configuration
type UpdateConfigRequest struct {
	Capacity      int64 `json:"capacity,omitempty"`
	RefillRate    int64 `json:"refill_rate,omitempty"`
	InitialTokens int64 `json:"initial_tokens,omitempty"`
}

// CheckRateLimitRequest represents a request to check rate limiting
type CheckRateLimitRequest struct {
	Key        string `json:"key" binding:"required"`
	Tokens     int64  `json:"tokens,omitempty"`
	ConfigName string `json:"config_name" binding:"required"`
}

// TestRateLimitRequest represents a request to test rate limiting
type TestRateLimitRequest struct {
	UserID      string            `json:"user_id"`
	OrgID       string            `json:"org_id"`
	IP          string            `json:"ip"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	RequestSize int64             `json:"request_size,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GetConfigs returns all rate limit configurations
func (api *RateLimitAPI) GetConfigs(c *gin.Context) {
	configNames, err := api.storage.GetConfigNames(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get config names: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get configurations"})
		return
	}
	
	configs := make(map[string]*BucketConfig)
	for _, name := range configNames {
		config, err := api.manager.GetConfig(c.Request.Context(), name)
		if err != nil {
			api.logger.Warnf("Failed to get config %s: %v", name, err)
			continue
		}
		configs[name] = config
	}
	
	c.JSON(http.StatusOK, gin.H{
		"configs": configs,
		"count":   len(configs),
	})
}

// CreateConfig creates a new rate limit configuration
func (api *RateLimitAPI) CreateConfig(c *gin.Context) {
	var req CreateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	config := &BucketConfig{
		Capacity:      req.Capacity,
		RefillRate:    req.RefillRate,
		InitialTokens: req.InitialTokens,
	}
	
	if err := api.manager.SetConfig(c.Request.Context(), req.Name, config); err != nil {
		api.logger.Errorf("Failed to create config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create configuration"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Configuration created successfully",
		"name":    req.Name,
		"config":  config,
	})
}

// GetConfig returns a specific rate limit configuration
func (api *RateLimitAPI) GetConfig(c *gin.Context) {
	name := c.Param("name")
	
	config, err := api.manager.GetConfig(c.Request.Context(), name)
	if err != nil {
		api.logger.Errorf("Failed to get config: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Configuration not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"name":   name,
		"config": config,
	})
}

// UpdateConfig updates an existing rate limit configuration
func (api *RateLimitAPI) UpdateConfig(c *gin.Context) {
	name := c.Param("name")
	
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Get existing config
	config, err := api.manager.GetConfig(c.Request.Context(), name)
	if err != nil {
		api.logger.Errorf("Failed to get config: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Configuration not found"})
		return
	}
	
	// Update fields
	if req.Capacity > 0 {
		config.Capacity = req.Capacity
	}
	if req.RefillRate > 0 {
		config.RefillRate = req.RefillRate
	}
	if req.InitialTokens >= 0 {
		config.InitialTokens = req.InitialTokens
	}
	
	if err := api.manager.SetConfig(c.Request.Context(), name, config); err != nil {
		api.logger.Errorf("Failed to update config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update configuration"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
		"name":    name,
		"config":  config,
	})
}

// DeleteConfig deletes a rate limit configuration
func (api *RateLimitAPI) DeleteConfig(c *gin.Context) {
	name := c.Param("name")
	
	// Note: This is a simplified implementation
	// In a real system, you'd want to check if the config is in use
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration deletion not implemented",
		"name":    name,
	})
}

// GetBuckets returns information about rate limit buckets
func (api *RateLimitAPI) GetBuckets(c *gin.Context) {
	pattern := c.Query("pattern")
	limit := c.Query("limit")
	
	bucketKeys, err := api.storage.GetBucketKeys(c.Request.Context(), pattern)
	if err != nil {
		api.logger.Errorf("Failed to get bucket keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get buckets"})
		return
	}
	
	// Apply limit if specified
	if limit != "" {
		if limitInt, err := strconv.Atoi(limit); err == nil && limitInt > 0 && limitInt < len(bucketKeys) {
			bucketKeys = bucketKeys[:limitInt]
		}
	}
	
	buckets := make(map[string]*RateLimitResult)
	for _, key := range bucketKeys {
		info, err := api.manager.GetBucketInfo(c.Request.Context(), key)
		if err != nil {
			api.logger.Warnf("Failed to get bucket info for %s: %v", key, err)
			continue
		}
		if info != nil {
			buckets[key] = info
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"buckets": buckets,
		"count":   len(buckets),
		"total":   len(bucketKeys),
	})
}

// GetBucket returns information about a specific bucket
func (api *RateLimitAPI) GetBucket(c *gin.Context) {
	key := c.Param("key")
	
	info, err := api.manager.GetBucketInfo(c.Request.Context(), key)
	if err != nil {
		api.logger.Errorf("Failed to get bucket info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get bucket information"})
		return
	}
	
	if info == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Bucket not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"key":    key,
		"bucket": info,
	})
}

// ResetBucket resets a specific bucket
func (api *RateLimitAPI) ResetBucket(c *gin.Context) {
	key := c.Param("key")
	
	if err := api.manager.ResetBucket(c.Request.Context(), key); err != nil {
		api.logger.Errorf("Failed to reset bucket: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset bucket"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Bucket reset successfully",
		"key":     key,
	})
}

// DeleteBucket deletes a specific bucket
func (api *RateLimitAPI) DeleteBucket(c *gin.Context) {
	key := c.Param("key")
	
	if err := api.storage.DeleteBucket(c.Request.Context(), key); err != nil {
		api.logger.Errorf("Failed to delete bucket: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete bucket"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Bucket deleted successfully",
		"key":     key,
	})
}

// CheckRateLimit checks rate limiting for a specific key
func (api *RateLimitAPI) CheckRateLimit(c *gin.Context) {
	var req CheckRateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	tokens := req.Tokens
	if tokens <= 0 {
		tokens = 1
	}
	
	result, err := api.manager.CheckRateLimit(c.Request.Context(), req.Key, tokens, req.ConfigName)
	if err != nil {
		api.logger.Errorf("Failed to check rate limit: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check rate limit"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"request": req,
		"result":  result,
	})
}

// CheckMultiLayerRateLimit checks multi-layer rate limiting
func (api *RateLimitAPI) CheckMultiLayerRateLimit(c *gin.Context) {
	var req TestRateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Create rate limit request
	rateLimitReq := &RateLimitRequest{
		UserID:      req.UserID,
		OrgID:       req.OrgID,
		IP:          req.IP,
		Endpoint:    req.Endpoint,
		Method:      req.Method,
		RequestSize: req.RequestSize,
		Timestamp:   time.Now(),
		Metadata:    req.Metadata,
	}
	
	result, err := api.limiter.CheckRateLimit(c.Request.Context(), rateLimitReq)
	if err != nil {
		api.logger.Errorf("Failed to check multi-layer rate limit: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check rate limit"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"request": rateLimitReq,
		"result":  result,
	})
}

// GetStats returns rate limiting statistics
func (api *RateLimitAPI) GetStats(c *gin.Context) {
	stats, err := api.manager.GetStats(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// CleanupExpired removes expired buckets
func (api *RateLimitAPI) CleanupExpired(c *gin.Context) {
	count, err := api.storage.CleanupExpiredBuckets(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to cleanup expired buckets: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cleanup expired buckets"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Cleanup completed",
		"removed": count,
	})
}

// TestRateLimit tests rate limiting with various scenarios
func (api *RateLimitAPI) TestRateLimit(c *gin.Context) {
	var req TestRateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Create rate limit request
	rateLimitReq := &RateLimitRequest{
		UserID:      req.UserID,
		OrgID:       req.OrgID,
		IP:          req.IP,
		Endpoint:    req.Endpoint,
		Method:      req.Method,
		RequestSize: req.RequestSize,
		Timestamp:   time.Now(),
		Metadata:    req.Metadata,
	}
	
	// Test with multi-layer limiter if available
	if api.limiter != nil {
		result, err := api.limiter.CheckRateLimit(c.Request.Context(), rateLimitReq)
		if err != nil {
			api.logger.Errorf("Failed to test rate limit: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test rate limit"})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"test_type": "multi_layer",
			"request":   rateLimitReq,
			"result":    result,
			"summary":   result.GetSummary(),
		})
		return
	}
	
	// Fallback to simple test
	c.JSON(http.StatusOK, gin.H{
		"test_type": "simple",
		"request":   rateLimitReq,
		"message":   "Multi-layer limiter not configured",
	})
}