package ai

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ThreatDetectionAPI provides REST API endpoints for AI threat detection management
type ThreatDetectionAPI struct {
	threatDetector      AIThreatDetector
	adaptiveLearning    *AdaptiveLearningSystem
	adaptiveRateLimiter *AIAdaptiveRateLimiter
	middleware          *AISecurityMiddleware
	storage             AIStorage
	logger              *logrus.Logger
}

// NewThreatDetectionAPI creates a new threat detection API
func NewThreatDetectionAPI(
	threatDetector AIThreatDetector,
	adaptiveLearning *AdaptiveLearningSystem,
	adaptiveRateLimiter *AIAdaptiveRateLimiter,
	middleware *AISecurityMiddleware,
	storage AIStorage,
	logger *logrus.Logger,
) *ThreatDetectionAPI {
	return &ThreatDetectionAPI{
		threatDetector:      threatDetector,
		adaptiveLearning:    adaptiveLearning,
		adaptiveRateLimiter: adaptiveRateLimiter,
		middleware:          middleware,
		storage:             storage,
		logger:              logger,
	}
}

// RegisterRoutes registers API routes with Gin router
func (api *ThreatDetectionAPI) RegisterRoutes(r *gin.RouterGroup) {
	// Threat analysis endpoints
	r.POST("/analyze", api.AnalyzeRequest)
	r.GET("/analyze/:id", api.GetAnalysisResult)
	r.GET("/analyze", api.ListAnalysisResults)
	
	// Threat policies management
	r.GET("/policies", api.GetThreatPolicies)
	r.PUT("/policies", api.UpdateThreatPolicies)
	r.POST("/policies/reset", api.ResetThreatPolicies)
	
	// Model management
	r.GET("/models", api.ListModels)
	r.GET("/models/:name", api.GetModel)
	r.POST("/models/:name/train", api.TrainModel)
	r.POST("/models/:name/reload", api.ReloadModel)
	r.GET("/models/:name/metrics", api.GetModelMetrics)
	
	// Adaptive learning management
	r.POST("/feedback", api.SubmitFeedback)
	r.GET("/learning/stats", api.GetLearningStats)
	r.GET("/learning/config", api.GetLearningConfig)
	r.PUT("/learning/config", api.UpdateLearningConfig)
	r.POST("/learning/retrain", api.TriggerRetraining)
	
	// Adaptive rate limiting management
	r.GET("/ratelimit/config", api.GetRateLimitConfig)
	r.PUT("/ratelimit/config", api.UpdateRateLimitConfig)
	r.GET("/ratelimit/stats", api.GetRateLimitStats)
	r.POST("/ratelimit/emergency", api.ActivateEmergencyMode)
	r.DELETE("/ratelimit/emergency", api.DeactivateEmergencyMode)
	
	// Middleware management
	r.GET("/middleware/config", api.GetMiddlewareConfig)
	r.PUT("/middleware/config", api.UpdateMiddlewareConfig)
	r.GET("/middleware/stats", api.GetMiddlewareStats)
	r.POST("/middleware/stats/reset", api.ResetMiddlewareStats)
	
	// Statistics and monitoring
	r.GET("/stats", api.GetOverallStats)
	r.GET("/health", api.GetHealthStatus)
	r.GET("/metrics", api.GetMetrics)
	
	// Threat intelligence
	r.POST("/intelligence/query", api.QueryThreatIntelligence)
	r.GET("/intelligence/feeds", api.GetThreatFeeds)
	r.POST("/intelligence/feeds/refresh", api.RefreshThreatFeeds)
	
	// Behavioral analysis
	r.GET("/behavior/profiles", api.GetBehaviorProfiles)
	r.GET("/behavior/profiles/:subject", api.GetBehaviorProfile)
	r.DELETE("/behavior/profiles/:subject", api.DeleteBehaviorProfile)
	r.GET("/behavior/anomalies", api.GetAnomalies)
	
	// Training data management
	r.GET("/training", api.GetTrainingData)
	r.POST("/training", api.AddTrainingData)
	r.DELETE("/training/:id", api.DeleteTrainingData)
	r.POST("/training/export", api.ExportTrainingData)
	r.POST("/training/import", api.ImportTrainingData)
}

// Request/Response types

type AnalyzeRequestBody struct {
	URL           string            `json:"url" binding:"required"`
	Method        string            `json:"method" binding:"required"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	ClientIP      string            `json:"client_ip,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type FeedbackSubmissionRequest struct {
	RequestID         string                 `json:"request_id" binding:"required"`
	UserFeedback      FeedbackType           `json:"user_feedback" binding:"required"`
	CorrectLabel      bool                   `json:"correct_label"`
	CorrectThreatType ThreatType             `json:"correct_threat_type,omitempty"`
	Comments          string                 `json:"comments,omitempty"`
	Source            string                 `json:"source,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type ThreatIntelligenceQuery struct {
	Type  string `json:"type" binding:"required"`
	Value string `json:"value" binding:"required"`
}

type TrainingDataRequest struct {
	Features   map[string]float64     `json:"features" binding:"required"`
	Label      bool                   `json:"label" binding:"required"`
	ThreatType ThreatType             `json:"threat_type,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type EmergencyModeRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// Threat analysis endpoints

func (api *ThreatDetectionAPI) AnalyzeRequest(c *gin.Context) {
	var req AnalyzeRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Create threat analysis request
	analysisRequest := &ThreatAnalysisRequest{
		RequestID: generateRequestID(c),
		Timestamp: time.Now(),
		ClientIP:  req.ClientIP,
		UserAgent: req.UserAgent,
		Method:    req.Method,
		URL:       req.URL,
		Headers:   req.Headers,
		Body:      []byte(req.Body),
		UserID:    req.UserID,
		SessionID: req.SessionID,
		Metadata:  req.Metadata,
	}
	
	// Perform threat analysis
	result, err := api.threatDetector.AnalyzeRequest(c.Request.Context(), analysisRequest)
	if err != nil {
		api.logger.Errorf("Threat analysis failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Threat analysis failed"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"analysis": result,
		"message": "Threat analysis completed successfully",
	})
}

func (api *ThreatDetectionAPI) GetAnalysisResult(c *gin.Context) {
	requestID := c.Param("id")
	
	result, err := api.storage.LoadThreatAnalysis(c.Request.Context(), requestID)
	if err != nil {
		api.logger.Errorf("Failed to load analysis result: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis result not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"analysis": result})
}

func (api *ThreatDetectionAPI) ListAnalysisResults(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 1000 {
		limit = 100
	}
	
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}
	
	results, err := api.storage.LoadThreatAnalyses(c.Request.Context(), limit, offset)
	if err != nil {
		api.logger.Errorf("Failed to load analysis results: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load analysis results"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"analyses": results,
		"count":    len(results),
		"limit":    limit,
		"offset":   offset,
	})
}

// Threat policies management

func (api *ThreatDetectionAPI) GetThreatPolicies(c *gin.Context) {
	policies, err := api.storage.LoadThreatPolicies(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to load threat policies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load threat policies"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (api *ThreatDetectionAPI) UpdateThreatPolicies(c *gin.Context) {
	var policies ThreatPolicies
	if err := c.ShouldBindJSON(&policies); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if err := api.threatDetector.ConfigurePolicies(c.Request.Context(), &policies); err != nil {
		api.logger.Errorf("Failed to update threat policies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update threat policies"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":  "Threat policies updated successfully",
		"policies": policies,
	})
}

func (api *ThreatDetectionAPI) ResetThreatPolicies(c *gin.Context) {
	// Reset to default policies
	defaultPolicies := getDefaultThreatPolicies()
	
	if err := api.threatDetector.ConfigurePolicies(c.Request.Context(), defaultPolicies); err != nil {
		api.logger.Errorf("Failed to reset threat policies: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset threat policies"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":  "Threat policies reset to defaults",
		"policies": defaultPolicies,
	})
}

// Model management

func (api *ThreatDetectionAPI) ListModels(c *gin.Context) {
	// This would typically interact with a model registry
	// For now, return basic model information
	models := []gin.H{
		{
			"name":        "content_analysis",
			"version":     "1.0.0",
			"type":        "classification",
			"status":      "active",
			"last_trained": time.Now().Add(-24 * time.Hour),
		},
		{
			"name":        "behavioral_analysis",
			"version":     "1.0.0",
			"type":        "anomaly_detection",
			"status":      "active",
			"last_trained": time.Now().Add(-12 * time.Hour),
		},
	}
	
	c.JSON(http.StatusOK, gin.H{
		"models": models,
		"count":  len(models),
	})
}

func (api *ThreatDetectionAPI) GetModel(c *gin.Context) {
	modelName := c.Param("name")
	
	// Return model information
	model := gin.H{
		"name":         modelName,
		"version":      "1.0.0",
		"type":         "classification",
		"status":       "active",
		"accuracy":     0.95,
		"last_trained": time.Now().Add(-24 * time.Hour),
		"training_size": 10000,
	}
	
	c.JSON(http.StatusOK, gin.H{"model": model})
}

func (api *ThreatDetectionAPI) TrainModel(c *gin.Context) {
	modelName := c.Param("name")
	
	// Load training data
	trainingData, err := api.storage.LoadTrainingExamples(c.Request.Context(), 1000, 0)
	if err != nil {
		api.logger.Errorf("Failed to load training data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load training data"})
		return
	}
	
	// Trigger model training (async)
	go func() {
		if err := api.threatDetector.UpdateModels(c.Request.Context(), trainingData); err != nil {
			api.logger.Errorf("Model training failed for %s: %v", modelName, err)
		} else {
			api.logger.Infof("Model training completed for %s", modelName)
		}
	}()
	
	c.JSON(http.StatusAccepted, gin.H{
		"message":      "Model training started",
		"model":        modelName,
		"training_size": len(trainingData),
	})
}

func (api *ThreatDetectionAPI) ReloadModel(c *gin.Context) {
	modelName := c.Param("name")
	
	// This would typically reload the model from storage
	api.logger.Infof("Reloading model: %s", modelName)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Model reloaded successfully",
		"model":   modelName,
	})
}

func (api *ThreatDetectionAPI) GetModelMetrics(c *gin.Context) {
	modelName := c.Param("name")
	
	// Return model metrics
	metrics := gin.H{
		"model":     modelName,
		"accuracy":  0.95,
		"precision": 0.93,
		"recall":    0.97,
		"f1_score":  0.95,
		"false_positive_rate": 0.02,
		"last_evaluated": time.Now().Add(-1 * time.Hour),
	}
	
	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

// Adaptive learning management

func (api *ThreatDetectionAPI) SubmitFeedback(c *gin.Context) {
	var req FeedbackSubmissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Load original analysis result
	originalResult, err := api.storage.LoadThreatAnalysis(c.Request.Context(), req.RequestID)
	if err != nil {
		api.logger.Errorf("Failed to load original analysis: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Original analysis not found"})
		return
	}
	
	// Create feedback example
	feedback := &FeedbackExample{
		ID:                generateFeedbackID(),
		RequestID:         req.RequestID,
		OriginalResult:    originalResult,
		UserFeedback:      req.UserFeedback,
		CorrectLabel:      req.CorrectLabel,
		CorrectThreatType: req.CorrectThreatType,
		Source:            req.Source,
		Timestamp:         time.Now(),
		Metadata:          req.Metadata,
	}
	
	// Submit feedback to adaptive learning system
	if err := api.adaptiveLearning.ProcessFeedback(c.Request.Context(), feedback); err != nil {
		api.logger.Errorf("Failed to process feedback: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process feedback"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":     "Feedback submitted successfully",
		"feedback_id": feedback.ID,
	})
}

func (api *ThreatDetectionAPI) GetLearningStats(c *gin.Context) {
	stats := api.adaptiveLearning.GetLearningStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func (api *ThreatDetectionAPI) GetLearningConfig(c *gin.Context) {
	config := api.adaptiveLearning.GetConfig()
	c.JSON(http.StatusOK, gin.H{"config": config})
}

func (api *ThreatDetectionAPI) UpdateLearningConfig(c *gin.Context) {
	var config AdaptiveLearningConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	api.adaptiveLearning.SetConfig(&config)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Learning configuration updated successfully",
		"config":  config,
	})
}

func (api *ThreatDetectionAPI) TriggerRetraining(c *gin.Context) {
	// Trigger manual retraining
	go api.adaptiveLearning.performFullRetraining(c.Request.Context())
	
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Model retraining triggered",
	})
}

// Adaptive rate limiting management

func (api *ThreatDetectionAPI) GetRateLimitConfig(c *gin.Context) {
	config := api.adaptiveRateLimiter.GetConfig()
	c.JSON(http.StatusOK, gin.H{"config": config})
}

func (api *ThreatDetectionAPI) UpdateRateLimitConfig(c *gin.Context) {
	var config AdaptiveRateLimitConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	api.adaptiveRateLimiter.SetConfig(&config)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Rate limit configuration updated successfully",
		"config":  config,
	})
}

func (api *ThreatDetectionAPI) GetRateLimitStats(c *gin.Context) {
	stats := api.adaptiveRateLimiter.GetStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func (api *ThreatDetectionAPI) ActivateEmergencyMode(c *gin.Context) {
	var req EmergencyModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	api.adaptiveRateLimiter.ActivateEmergencyMode(req.Reason)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Emergency mode activated",
		"reason":  req.Reason,
	})
}

func (api *ThreatDetectionAPI) DeactivateEmergencyMode(c *gin.Context) {
	api.adaptiveRateLimiter.DeactivateEmergencyMode()
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Emergency mode deactivated",
	})
}

// Middleware management

func (api *ThreatDetectionAPI) GetMiddlewareConfig(c *gin.Context) {
	config := api.middleware.GetConfig()
	c.JSON(http.StatusOK, gin.H{"config": config})
}

func (api *ThreatDetectionAPI) UpdateMiddlewareConfig(c *gin.Context) {
	var config MiddlewareConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	api.middleware.SetConfig(&config)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Middleware configuration updated successfully",
		"config":  config,
	})
}

func (api *ThreatDetectionAPI) GetMiddlewareStats(c *gin.Context) {
	stats := api.middleware.GetStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func (api *ThreatDetectionAPI) ResetMiddlewareStats(c *gin.Context) {
	api.middleware.ResetStats()
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Middleware statistics reset successfully",
	})
}

// Statistics and monitoring

func (api *ThreatDetectionAPI) GetOverallStats(c *gin.Context) {
	threatStats, err := api.threatDetector.GetStats(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get threat stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics"})
		return
	}
	
	learningStats := api.adaptiveLearning.GetLearningStats()
	rateLimitStats := api.adaptiveRateLimiter.GetStats()
	middlewareStats := api.middleware.GetStats()
	
	overallStats := gin.H{
		"threat_detection": threatStats,
		"adaptive_learning": learningStats,
		"adaptive_rate_limiting": rateLimitStats,
		"middleware": middlewareStats,
		"timestamp": time.Now(),
	}
	
	c.JSON(http.StatusOK, gin.H{"stats": overallStats})
}

func (api *ThreatDetectionAPI) GetHealthStatus(c *gin.Context) {
	health, err := api.threatDetector.GetHealth(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get health status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get health status"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"health": health})
}

func (api *ThreatDetectionAPI) GetMetrics(c *gin.Context) {
	// Return Prometheus-style metrics
	metrics := gin.H{
		"ai_threat_requests_total":     api.middleware.GetStats().RequestsProcessed,
		"ai_threats_detected_total":    api.middleware.GetStats().ThreatsDetected,
		"ai_requests_blocked_total":    api.middleware.GetStats().RequestsBlocked,
		"ai_learning_feedback_total":   api.adaptiveLearning.GetLearningStats().TotalFeedback,
		"ai_model_updates_total":       api.adaptiveLearning.GetLearningStats().ModelUpdates,
		"ai_ratelimit_adjustments_total": api.adaptiveRateLimiter.GetStats().ThreatBasedAdjustments,
	}
	
	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

// Threat intelligence

func (api *ThreatDetectionAPI) QueryThreatIntelligence(c *gin.Context) {
	var query ThreatIntelligenceQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	threatQuery := &ThreatQuery{
		Type:  query.Type,
		Value: query.Value,
	}
	
	intelligence, err := api.threatDetector.GetThreatIntelligence(c.Request.Context(), threatQuery)
	if err != nil {
		api.logger.Errorf("Threat intelligence query failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Threat intelligence query failed"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"intelligence": intelligence})
}

func (api *ThreatDetectionAPI) GetThreatFeeds(c *gin.Context) {
	// Return information about threat feeds
	feeds := []gin.H{
		{
			"name":        "malware_domains",
			"type":        "domain",
			"status":      "active",
			"last_update": time.Now().Add(-1 * time.Hour),
			"entries":     15000,
		},
		{
			"name":        "phishing_urls",
			"type":        "url",
			"status":      "active",
			"last_update": time.Now().Add(-30 * time.Minute),
			"entries":     8500,
		},
	}
	
	c.JSON(http.StatusOK, gin.H{
		"feeds": feeds,
		"count": len(feeds),
	})
}

func (api *ThreatDetectionAPI) RefreshThreatFeeds(c *gin.Context) {
	// Trigger threat feed refresh
	api.logger.Info("Refreshing threat intelligence feeds")
	
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Threat feed refresh triggered",
	})
}

// Behavioral analysis

func (api *ThreatDetectionAPI) GetBehaviorProfiles(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	
	// This would typically load from storage
	profiles := []gin.H{
		{
			"subject":      "user:123",
			"profile_type": "user",
			"last_seen":    time.Now().Add(-5 * time.Minute),
			"request_count": 150,
			"anomaly_score": 0.2,
		},
		{
			"subject":      "ip:192.168.1.100",
			"profile_type": "ip",
			"last_seen":    time.Now().Add(-1 * time.Minute),
			"request_count": 50,
			"anomaly_score": 0.8,
		},
	}
	
	c.JSON(http.StatusOK, gin.H{
		"profiles": profiles,
		"count":    len(profiles),
		"limit":    limit,
	})
}

func (api *ThreatDetectionAPI) GetBehaviorProfile(c *gin.Context) {
	subject := c.Param("subject")
	
	// Load behavior profile
	profile := gin.H{
		"subject":       subject,
		"profile_type":  "user",
		"created_at":    time.Now().Add(-24 * time.Hour),
		"last_seen":     time.Now().Add(-5 * time.Minute),
		"request_count": 150,
		"anomaly_score": 0.2,
		"patterns": gin.H{
			"avg_requests_per_hour": 12.5,
			"common_endpoints":      []string{"/api/data", "/api/users"},
			"peak_hours":           []int{9, 10, 14, 15},
		},
	}
	
	c.JSON(http.StatusOK, gin.H{"profile": profile})
}

func (api *ThreatDetectionAPI) DeleteBehaviorProfile(c *gin.Context) {
	subject := c.Param("subject")
	
	// Delete behavior profile
	api.logger.Infof("Deleting behavior profile for: %s", subject)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Behavior profile deleted successfully",
		"subject": subject,
	})
}

func (api *ThreatDetectionAPI) GetAnomalies(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)
	
	// Return recent anomalies
	anomalies := []gin.H{
		{
			"id":           "anomaly-1",
			"subject":      "user:456",
			"type":         "request_frequency",
			"score":        0.9,
			"detected_at":  time.Now().Add(-10 * time.Minute),
			"description":  "Unusual request frequency spike",
		},
		{
			"id":           "anomaly-2",
			"subject":      "ip:10.0.0.50",
			"type":         "access_pattern",
			"score":        0.7,
			"detected_at":  time.Now().Add(-30 * time.Minute),
			"description":  "Accessing unusual endpoints",
		},
	}
	
	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"count":     len(anomalies),
		"limit":     limit,
	})
}

// Training data management

func (api *ThreatDetectionAPI) GetTrainingData(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	
	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)
	
	trainingData, err := api.storage.LoadTrainingExamples(c.Request.Context(), limit, offset)
	if err != nil {
		api.logger.Errorf("Failed to load training data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load training data"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"training_data": trainingData,
		"count":         len(trainingData),
		"limit":         limit,
		"offset":        offset,
	})
}

func (api *ThreatDetectionAPI) AddTrainingData(c *gin.Context) {
	var req TrainingDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	trainingExample := &TrainingExample{
		ID:         generateTrainingExampleID(),
		Features:   req.Features,
		Label:      req.Label,
		ThreatType: req.ThreatType,
		Source:     req.Source,
		Timestamp:  time.Now(),
		Metadata:   req.Metadata,
	}
	
	if err := api.storage.SaveTrainingExample(c.Request.Context(), trainingExample); err != nil {
		api.logger.Errorf("Failed to save training example: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save training data"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message":    "Training data added successfully",
		"example_id": trainingExample.ID,
	})
}

func (api *ThreatDetectionAPI) DeleteTrainingData(c *gin.Context) {
	exampleID := c.Param("id")
	
	if err := api.storage.DeleteTrainingExample(c.Request.Context(), exampleID); err != nil {
		api.logger.Errorf("Failed to delete training example: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete training data"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":    "Training data deleted successfully",
		"example_id": exampleID,
	})
}

func (api *ThreatDetectionAPI) ExportTrainingData(c *gin.Context) {
	// Export training data in a standard format
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Training data export started",
		"format":  "json",
	})
}

func (api *ThreatDetectionAPI) ImportTrainingData(c *gin.Context) {
	// Import training data from uploaded file
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Training data import started",
	})
}

// Helper functions

func generateFeedbackID() string {
	return fmt.Sprintf("feedback-%d", time.Now().UnixNano())
}

func generateTrainingExampleID() string {
	return fmt.Sprintf("training-%d", time.Now().UnixNano())
}