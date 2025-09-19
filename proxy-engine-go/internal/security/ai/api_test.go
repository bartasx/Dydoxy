package ai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestAPI() (*ThreatDetectionAPI, *gin.Engine) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	adaptiveLearning := NewAdaptiveLearningSystem(&MockAIStorage{}, threatDetector, &MockModelManager{}, logger)
	adaptiveRateLimiter := NewAIAdaptiveRateLimiter(threatDetector, &MockMultiLayerRateLimiter{}, nil, nil, logger)
	middleware := NewAISecurityMiddleware(threatDetector, logger)
	storage := &MockAIStorage{}
	
	api := NewThreatDetectionAPI(threatDetector, adaptiveLearning, adaptiveRateLimiter, middleware, storage, logger)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	apiGroup := router.Group("/api/v1/ai")
	api.RegisterRoutes(apiGroup)
	
	return api, router
}

func TestThreatDetectionAPI_AnalyzeRequest(t *testing.T) {
	api, router := setupTestAPI()
	
	requestBody := AnalyzeRequestBody{
		URL:       "https://example.com/test",
		Method:    "GET",
		ClientIP:  "192.168.1.1",
		UserAgent: "test-agent",
		Headers:   map[string]string{"Content-Type": "application/json"},
	}
	
	threatAnalysis := &ThreatAnalysisResult{
		RequestID:   "test-req-123",
		IsThreat:    false,
		ThreatLevel: ThreatLevelLow,
		Confidence:  0.2,
		Timestamp:   time.Now(),
	}
	
	// Mock threat detector
	mockDetector := api.threatDetector.(*MockAIThreatDetector)
	mockDetector.On("AnalyzeRequest", mock.Anything, mock.AnythingOfType("*ai.ThreatAnalysisRequest")).Return(threatAnalysis, nil)
	
	// Make request
	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/v1/ai/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "analysis")
	assert.Contains(t, response, "message")
	
	mockDetector.AssertExpectations(t)
}

func TestThreatDetectionAPI_AnalyzeRequest_InvalidBody(t *testing.T) {
	_, router := setupTestAPI()
	
	// Invalid request body (missing required fields)
	requestBody := map[string]interface{}{
		"invalid": "data",
	}
	
	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/v1/ai/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "error")
}

func TestThreatDetectionAPI_GetAnalysisResult(t *testing.T) {
	api, router := setupTestAPI()
	
	requestID := "test-req-123"
	threatAnalysis := &ThreatAnalysisResult{
		RequestID:   requestID,
		IsThreat:    true,
		ThreatLevel: ThreatLevelHigh,
		Confidence:  0.9,
		Timestamp:   time.Now(),
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("LoadThreatAnalysis", mock.Anything, requestID).Return(threatAnalysis, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/analyze/"+requestID, nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "analysis")
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_ListAnalysisResults(t *testing.T) {
	api, router := setupTestAPI()
	
	results := []*ThreatAnalysisResult{
		{
			RequestID:   "req-1",
			IsThreat:    false,
			ThreatLevel: ThreatLevelLow,
			Timestamp:   time.Now(),
		},
		{
			RequestID:   "req-2",
			IsThreat:    true,
			ThreatLevel: ThreatLevelHigh,
			Timestamp:   time.Now(),
		},
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("LoadThreatAnalyses", mock.Anything, 100, 0).Return(results, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/analyze", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "analyses")
	assert.Equal(t, float64(2), response["count"])
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_GetThreatPolicies(t *testing.T) {
	api, router := setupTestAPI()
	
	policies := &ThreatPolicies{
		GlobalEnabled:       true,
		ConfidenceThreshold: 0.7,
		BehavioralAnalysis:  true,
		MachineLearning:     true,
		ThreatIntelligence:  true,
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("LoadThreatPolicies", mock.Anything).Return(policies, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/policies", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "policies")
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_UpdateThreatPolicies(t *testing.T) {
	api, router := setupTestAPI()
	
	policies := ThreatPolicies{
		GlobalEnabled:       false,
		ConfidenceThreshold: 0.8,
		BehavioralAnalysis:  false,
		MachineLearning:     true,
		ThreatIntelligence:  true,
	}
	
	// Mock threat detector
	mockDetector := api.threatDetector.(*MockAIThreatDetector)
	mockDetector.On("ConfigurePolicies", mock.Anything, &policies).Return(nil)
	
	body, _ := json.Marshal(policies)
	req := httptest.NewRequest("PUT", "/api/v1/ai/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "policies")
	
	mockDetector.AssertExpectations(t)
}

func TestThreatDetectionAPI_SubmitFeedback(t *testing.T) {
	api, router := setupTestAPI()
	
	requestID := "test-req-123"
	feedbackReq := FeedbackSubmissionRequest{
		RequestID:         requestID,
		UserFeedback:      FeedbackFalsePositive,
		CorrectLabel:      false,
		CorrectThreatType: ThreatTypeNone,
		Comments:          "This was not a threat",
		Source:            "user",
	}
	
	originalResult := &ThreatAnalysisResult{
		RequestID:   requestID,
		IsThreat:    true,
		ThreatLevel: ThreatLevelHigh,
		Confidence:  0.9,
		Timestamp:   time.Now(),
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("LoadThreatAnalysis", mock.Anything, requestID).Return(originalResult, nil)
	mockStorage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil)
	
	body, _ := json.Marshal(feedbackReq)
	req := httptest.NewRequest("POST", "/api/v1/ai/feedback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "feedback_id")
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_GetLearningStats(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("GET", "/api/v1/ai/learning/stats", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "stats")
}

func TestThreatDetectionAPI_UpdateLearningConfig(t *testing.T) {
	_, router := setupTestAPI()
	
	config := AdaptiveLearningConfig{
		EnabledLearning:        false,
		FeedbackBufferSize:     500,
		MinFeedbackForUpdate:   25,
		LearningRate:           0.005,
		PerformanceThreshold:   0.9,
		EnableAutoRetraining:   false,
		EnableFeedbackLearning: false,
	}
	
	body, _ := json.Marshal(config)
	req := httptest.NewRequest("PUT", "/api/v1/ai/learning/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "config")
}

func TestThreatDetectionAPI_GetRateLimitStats(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("GET", "/api/v1/ai/ratelimit/stats", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "stats")
}

func TestThreatDetectionAPI_ActivateEmergencyMode(t *testing.T) {
	_, router := setupTestAPI()
	
	emergencyReq := EmergencyModeRequest{
		Reason: "High threat activity detected",
	}
	
	body, _ := json.Marshal(emergencyReq)
	req := httptest.NewRequest("POST", "/api/v1/ai/ratelimit/emergency", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "reason")
}

func TestThreatDetectionAPI_DeactivateEmergencyMode(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("DELETE", "/api/v1/ai/ratelimit/emergency", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
}

func TestThreatDetectionAPI_GetOverallStats(t *testing.T) {
	api, router := setupTestAPI()
	
	threatStats := &AIThreatStats{
		TotalRequests:         1000,
		ThreatsDetected:       50,
		ThreatsByType:         make(map[ThreatType]int64),
		ThreatsByLevel:        make(map[ThreatLevel]int64),
		ActionsTaken:          make(map[ActionType]int64),
		ModelAccuracy:         make(map[string]float64),
		AverageProcessingTime: 100 * time.Millisecond,
		LastUpdated:           time.Now(),
	}
	
	// Mock threat detector
	mockDetector := api.threatDetector.(*MockAIThreatDetector)
	mockDetector.On("GetStats", mock.Anything).Return(threatStats, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/stats", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "stats")
	stats := response["stats"].(map[string]interface{})
	assert.Contains(t, stats, "threat_detection")
	assert.Contains(t, stats, "adaptive_learning")
	assert.Contains(t, stats, "adaptive_rate_limiting")
	assert.Contains(t, stats, "middleware")
	
	mockDetector.AssertExpectations(t)
}

func TestThreatDetectionAPI_GetHealthStatus(t *testing.T) {
	api, router := setupTestAPI()
	
	health := &AIHealthStatus{
		Overall:         "healthy",
		Components:      map[string]string{"storage": "healthy"},
		ModelStatus:     map[string]string{"content_model": "ready"},
		LastHealthCheck: time.Now(),
		Issues:          []string{},
		Metrics:         map[string]interface{}{"total_requests": 1000},
	}
	
	// Mock threat detector
	mockDetector := api.threatDetector.(*MockAIThreatDetector)
	mockDetector.On("GetHealth", mock.Anything).Return(health, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/health", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "health")
	
	mockDetector.AssertExpectations(t)
}

func TestThreatDetectionAPI_QueryThreatIntelligence(t *testing.T) {
	api, router := setupTestAPI()
	
	query := ThreatIntelligenceQuery{
		Type:  "domain",
		Value: "malicious.example.com",
	}
	
	intelligence := &ThreatIntelligence{
		Query: &ThreatQuery{
			Type:  query.Type,
			Value: query.Value,
		},
		IsThreat:    true,
		ThreatType:  ThreatTypeMalware,
		Confidence:  0.95,
		Patterns:    []*ThreatPattern{},
		Metadata:    map[string]interface{}{},
		Timestamp:   time.Now(),
	}
	
	// Mock threat detector
	mockDetector := api.threatDetector.(*MockAIThreatDetector)
	mockDetector.On("GetThreatIntelligence", mock.Anything, mock.AnythingOfType("*ai.ThreatQuery")).Return(intelligence, nil)
	
	body, _ := json.Marshal(query)
	req := httptest.NewRequest("POST", "/api/v1/ai/intelligence/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "intelligence")
	
	mockDetector.AssertExpectations(t)
}

func TestThreatDetectionAPI_AddTrainingData(t *testing.T) {
	api, router := setupTestAPI()
	
	trainingReq := TrainingDataRequest{
		Features: map[string]float64{
			"url_length":    50.0,
			"domain_age":    365.0,
			"has_https":     1.0,
		},
		Label:      false,
		ThreatType: ThreatTypeNone,
		Source:     "manual",
		Metadata:   map[string]interface{}{"category": "benign"},
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("SaveTrainingExample", mock.Anything, mock.AnythingOfType("*ai.TrainingExample")).Return(nil)
	
	body, _ := json.Marshal(trainingReq)
	req := httptest.NewRequest("POST", "/api/v1/ai/training", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusCreated, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "example_id")
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_GetTrainingData(t *testing.T) {
	api, router := setupTestAPI()
	
	trainingData := []*TrainingExample{
		{
			ID:       "example-1",
			Features: map[string]float64{"feature1": 1.0},
			Label:    true,
			Source:   "test",
		},
		{
			ID:       "example-2",
			Features: map[string]float64{"feature1": 0.5},
			Label:    false,
			Source:   "test",
		},
	}
	
	// Mock storage
	mockStorage := api.storage.(*MockAIStorage)
	mockStorage.On("LoadTrainingExamples", mock.Anything, 100, 0).Return(trainingData, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/ai/training", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "training_data")
	assert.Equal(t, float64(2), response["count"])
	
	mockStorage.AssertExpectations(t)
}

func TestThreatDetectionAPI_ListModels(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("GET", "/api/v1/ai/models", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "models")
	assert.Contains(t, response, "count")
	
	models := response["models"].([]interface{})
	assert.Greater(t, len(models), 0)
}

func TestThreatDetectionAPI_TriggerRetraining(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("POST", "/api/v1/ai/learning/retrain", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusAccepted, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "message")
}

func TestThreatDetectionAPI_GetMetrics(t *testing.T) {
	_, router := setupTestAPI()
	
	req := httptest.NewRequest("GET", "/api/v1/ai/metrics", nil)
	w := httptest.NewRecorder()
	
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Contains(t, response, "metrics")
	
	metrics := response["metrics"].(map[string]interface{})
	assert.Contains(t, metrics, "ai_threat_requests_total")
	assert.Contains(t, metrics, "ai_threats_detected_total")
	assert.Contains(t, metrics, "ai_requests_blocked_total")
}