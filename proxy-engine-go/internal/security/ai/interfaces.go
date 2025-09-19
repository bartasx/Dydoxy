package ai

import (
	"context"
	"net"
	"time"
)

// AIThreatDetector is the main interface for AI-powered threat detection
type AIThreatDetector interface {
	// AnalyzeRequest performs comprehensive threat analysis
	AnalyzeRequest(ctx context.Context, request *ThreatAnalysisRequest) (*ThreatAnalysisResult, error)
	
	// UpdateModels updates ML models with new training data
	UpdateModels(ctx context.Context, trainingData []*TrainingExample) error
	
	// GetThreatIntelligence retrieves current threat intelligence
	GetThreatIntelligence(ctx context.Context, query *ThreatQuery) (*ThreatIntelligence, error)
	
	// ConfigurePolicies updates threat detection policies
	ConfigurePolicies(ctx context.Context, policies *ThreatPolicies) error
	
	// GetStats returns current threat detection statistics
	GetStats(ctx context.Context) (*AIThreatStats, error)
	
	// GetHealth returns health status of AI components
	GetHealth(ctx context.Context) (*AIHealthStatus, error)
}

// MLModel represents a machine learning model for threat detection
type MLModel interface {
	// Predict performs inference on input features
	Predict(ctx context.Context, features map[string]float64) (*MLPrediction, error)
	
	// Train updates the model with new training data
	Train(ctx context.Context, examples []*TrainingExample) error
	
	// GetMetrics returns model performance metrics
	GetMetrics(ctx context.Context) (*ModelMetrics, error)
	
	// Export exports the model for backup or deployment
	Export(ctx context.Context) ([]byte, error)
	
	// Import imports a model from backup
	Import(ctx context.Context, data []byte) error
	
	// GetVersion returns the model version
	GetVersion() string
	
	// IsReady returns true if the model is ready for inference
	IsReady() bool
}

// BehavioralAnalyzer analyzes user and IP behavior patterns
type BehavioralAnalyzer interface {
	// AnalyzeBehavior analyzes behavior for anomalies
	AnalyzeBehavior(ctx context.Context, subject string, request *RequestContext) (*BehaviorAnalysis, error)
	
	// UpdateProfile updates behavioral profile
	UpdateProfile(ctx context.Context, subject string, request *RequestContext) error
	
	// GetProfile retrieves behavioral profile
	GetProfile(ctx context.Context, subject string) (*BehaviorProfile, error)
	
	// DetectAnomalies detects behavioral anomalies
	DetectAnomalies(ctx context.Context, subject string, request *RequestContext) (bool, float64, error)
	
	// TrainModel trains the behavioral analysis model
	TrainModel(ctx context.Context, data []*RequestContext) error
}

// FeatureExtractor extracts features from requests for ML analysis
type FeatureExtractor interface {
	// ExtractFeatures converts a request to feature vector
	ExtractFeatures(ctx context.Context, request *ThreatAnalysisRequest) (*FeatureVector, error)
	
	// ExtractBehavioralFeatures extracts behavioral features
	ExtractBehavioralFeatures(ctx context.Context, subject string, request *RequestContext) (map[string]float64, error)
	
	// GetFeatureNames returns list of feature names
	GetFeatureNames() []string
	
	// ValidateFeatures validates feature vector completeness
	ValidateFeatures(features *FeatureVector) error
}

// ModelManager manages ML model lifecycle
type ModelManager interface {
	// LoadModel loads a model by name and version
	LoadModel(ctx context.Context, name, version string) (MLModel, error)
	
	// SaveModel saves a model with version
	SaveModel(ctx context.Context, name, version string, model MLModel) error
	
	// ListModels returns available models
	ListModels(ctx context.Context) ([]*ModelInfo, error)
	
	// GetLatestVersion returns the latest version of a model
	GetLatestVersion(ctx context.Context, name string) (string, error)
	
	// DeleteModel deletes a model version
	DeleteModel(ctx context.Context, name, version string) error
	
	// SetActiveModel sets the active version for a model
	SetActiveModel(ctx context.Context, name, version string) error
}

// ThreatIntelligenceService provides threat intelligence data
type ThreatIntelligenceService interface {
	// GetThreatIntelligence retrieves threat intelligence for a query
	GetThreatIntelligence(ctx context.Context, query *ThreatQuery) (*ThreatIntelligence, error)
	
	// UpdateThreatFeeds updates threat intelligence from external feeds
	UpdateThreatFeeds(ctx context.Context) error
	
	// GetIPReputation gets reputation information for an IP
	GetIPReputation(ctx context.Context, ip net.IP) (*IPThreatReputation, error)
	
	// GetDomainReputation gets reputation information for a domain
	GetDomainReputation(ctx context.Context, domain string) (*DomainThreatReputation, error)
	
	// CheckThreatPatterns checks if request matches known threat patterns
	CheckThreatPatterns(ctx context.Context, request *ThreatAnalysisRequest) ([]*ThreatPattern, error)
}

// AIStorage defines storage interface for AI components
type AIStorage interface {
	// Model storage
	SaveModel(ctx context.Context, name, version string, data []byte) error
	LoadModel(ctx context.Context, name, version string) ([]byte, error)
	ListModels(ctx context.Context) ([]*ModelInfo, error)
	DeleteModel(ctx context.Context, name, version string) error
	
	// Training data storage
	SaveTrainingExample(ctx context.Context, example *TrainingExample) error
	LoadTrainingExamples(ctx context.Context, limit int, offset int) ([]*TrainingExample, error)
	
	// Behavioral profiles storage
	SaveBehaviorProfile(ctx context.Context, subject string, profile *BehaviorProfile) error
	LoadBehaviorProfile(ctx context.Context, subject string) (*BehaviorProfile, error)
	
	// Threat analysis results storage
	SaveThreatAnalysis(ctx context.Context, result *ThreatAnalysisResult) error
	LoadThreatAnalysis(ctx context.Context, requestID string) (*ThreatAnalysisResult, error)
	
	// Statistics storage
	SaveAIStats(ctx context.Context, stats *AIThreatStats) error
	LoadAIStats(ctx context.Context) (*AIThreatStats, error)
	
	// Configuration storage
	SaveThreatPolicies(ctx context.Context, policies *ThreatPolicies) error
	LoadThreatPolicies(ctx context.Context) (*ThreatPolicies, error)
}

// AlertManager manages threat detection alerts
type AlertManager interface {
	// CreateAlert creates a new threat alert
	CreateAlert(ctx context.Context, alert *ThreatAlert) error
	
	// GetAlerts retrieves alerts based on criteria
	GetAlerts(ctx context.Context, level AlertLevel, resolved bool, limit int) ([]*ThreatAlert, error)
	
	// ResolveAlert marks an alert as resolved
	ResolveAlert(ctx context.Context, alertID string) error
	
	// SendAlert sends an alert through configured channels
	SendAlert(ctx context.Context, alert *ThreatAlert) error
	
	// GetUnresolvedAlerts returns all unresolved alerts
	GetUnresolvedAlerts(ctx context.Context) ([]*ThreatAlert, error)
}