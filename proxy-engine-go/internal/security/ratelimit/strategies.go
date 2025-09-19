package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// RateLimitStrategy defines different rate limiting strategies
type RateLimitStrategy interface {
	// GetBucketKey generates a bucket key for the request
	GetBucketKey(request *RateLimitRequest) string
	
	// GetConfigName returns the configuration name to use
	GetConfigName(request *RateLimitRequest) string
	
	// GetTokensRequired returns the number of tokens required
	GetTokensRequired(request *RateLimitRequest) int64
	
	// GetStrategyName returns the name of the strategy
	GetStrategyName() string
}

// RateLimitRequest represents a request to be rate limited
type RateLimitRequest struct {
	UserID       string            `json:"user_id"`
	OrgID        string            `json:"org_id"`
	IP           string            `json:"ip"`
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	UserAgent    string            `json:"user_agent"`
	Headers      map[string]string `json:"headers"`
	RequestSize  int64             `json:"request_size"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PerUserStrategy implements per-user rate limiting
type PerUserStrategy struct {
	configName string
}

// NewPerUserStrategy creates a new per-user rate limiting strategy
func NewPerUserStrategy(configName string) *PerUserStrategy {
	return &PerUserStrategy{
		configName: configName,
	}
}

func (s *PerUserStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("user:%s", request.UserID)
}

func (s *PerUserStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *PerUserStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *PerUserStrategy) GetStrategyName() string {
	return "per_user"
}

// PerIPStrategy implements per-IP rate limiting
type PerIPStrategy struct {
	configName string
}

// NewPerIPStrategy creates a new per-IP rate limiting strategy
func NewPerIPStrategy(configName string) *PerIPStrategy {
	return &PerIPStrategy{
		configName: configName,
	}
}

func (s *PerIPStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("ip:%s", request.IP)
}

func (s *PerIPStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *PerIPStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *PerIPStrategy) GetStrategyName() string {
	return "per_ip"
}

// PerOrgStrategy implements per-organization rate limiting
type PerOrgStrategy struct {
	configName string
}

// NewPerOrgStrategy creates a new per-organization rate limiting strategy
func NewPerOrgStrategy(configName string) *PerOrgStrategy {
	return &PerOrgStrategy{
		configName: configName,
	}
}

func (s *PerOrgStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("org:%s", request.OrgID)
}

func (s *PerOrgStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *PerOrgStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *PerOrgStrategy) GetStrategyName() string {
	return "per_org"
}

// PerEndpointStrategy implements per-endpoint rate limiting
type PerEndpointStrategy struct {
	configName string
}

// NewPerEndpointStrategy creates a new per-endpoint rate limiting strategy
func NewPerEndpointStrategy(configName string) *PerEndpointStrategy {
	return &PerEndpointStrategy{
		configName: configName,
	}
}

func (s *PerEndpointStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("endpoint:%s:%s", request.Method, request.Endpoint)
}

func (s *PerEndpointStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *PerEndpointStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *PerEndpointStrategy) GetStrategyName() string {
	return "per_endpoint"
}

// CompositeStrategy implements composite rate limiting (user + IP)
type CompositeStrategy struct {
	configName string
}

// NewCompositeStrategy creates a new composite rate limiting strategy
func NewCompositeStrategy(configName string) *CompositeStrategy {
	return &CompositeStrategy{
		configName: configName,
	}
}

func (s *CompositeStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("composite:%s:%s", request.UserID, request.IP)
}

func (s *CompositeStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *CompositeStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *CompositeStrategy) GetStrategyName() string {
	return "composite"
}

// SizeBasedStrategy implements size-based rate limiting
type SizeBasedStrategy struct {
	configName      string
	bytesPerToken   int64
	minTokens       int64
}

// NewSizeBasedStrategy creates a new size-based rate limiting strategy
func NewSizeBasedStrategy(configName string, bytesPerToken, minTokens int64) *SizeBasedStrategy {
	return &SizeBasedStrategy{
		configName:    configName,
		bytesPerToken: bytesPerToken,
		minTokens:     minTokens,
	}
}

func (s *SizeBasedStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("size:%s", request.UserID)
}

func (s *SizeBasedStrategy) GetConfigName(request *RateLimitRequest) string {
	return s.configName
}

func (s *SizeBasedStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	if request.RequestSize <= 0 {
		return s.minTokens
	}
	
	tokens := request.RequestSize / s.bytesPerToken
	if tokens < s.minTokens {
		tokens = s.minTokens
	}
	
	return tokens
}

func (s *SizeBasedStrategy) GetStrategyName() string {
	return "size_based"
}

// TieredStrategy implements tiered rate limiting based on user tier
type TieredStrategy struct {
	tierConfigs map[string]string // tier -> config name mapping
	defaultConfig string
}

// NewTieredStrategy creates a new tiered rate limiting strategy
func NewTieredStrategy(tierConfigs map[string]string, defaultConfig string) *TieredStrategy {
	return &TieredStrategy{
		tierConfigs:   tierConfigs,
		defaultConfig: defaultConfig,
	}
}

func (s *TieredStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("tiered:%s", request.UserID)
}

func (s *TieredStrategy) GetConfigName(request *RateLimitRequest) string {
	// Try to get tier from metadata
	if tier, exists := request.Metadata["tier"]; exists {
		if tierStr, ok := tier.(string); ok {
			if config, exists := s.tierConfigs[tierStr]; exists {
				return config
			}
		}
	}
	
	return s.defaultConfig
}

func (s *TieredStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	return 1
}

func (s *TieredStrategy) GetStrategyName() string {
	return "tiered"
}

// UserOrgAwareStrategy implements user/org aware rate limiting
type UserOrgAwareStrategy struct {
	limitManager *UserOrgLimitManager
	limitType    LimitType
}

// NewUserOrgAwareStrategy creates a new user/org aware rate limiting strategy
func NewUserOrgAwareStrategy(limitManager *UserOrgLimitManager, limitType LimitType) *UserOrgAwareStrategy {
	return &UserOrgAwareStrategy{
		limitManager: limitManager,
		limitType:    limitType,
	}
}

func (s *UserOrgAwareStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("user_org:%s:%s:%s", request.UserID, request.OrgID, s.limitType)
}

func (s *UserOrgAwareStrategy) GetConfigName(request *RateLimitRequest) string {
	// This strategy uses dynamic configuration based on user/org limits
	return fmt.Sprintf("dynamic_%s", s.limitType)
}

func (s *UserOrgAwareStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	switch s.limitType {
	case LimitTypeBandwidthPerDay, LimitTypeBandwidthPerMonth:
		return request.RequestSize
	default:
		return 1
	}
}

func (s *UserOrgAwareStrategy) GetStrategyName() string {
	return fmt.Sprintf("user_org_%s", s.limitType)
}

// CheckLimit checks user/org limits directly
func (s *UserOrgAwareStrategy) CheckLimit(ctx context.Context, request *RateLimitRequest) (*LimitCheckResult, error) {
	limitRequest := &LimitCheckRequest{
		UserID:      request.UserID,
		OrgID:       request.OrgID,
		LimitType:   s.limitType,
		Amount:      s.GetTokensRequired(request),
		RequestSize: request.RequestSize,
		Timestamp:   request.Timestamp,
	}
	
	return s.limitManager.CheckLimits(ctx, limitRequest)
}

// HierarchicalStrategy implements hierarchical rate limiting (org -> user)
type HierarchicalStrategy struct {
	limitManager *UserOrgLimitManager
	limitType    LimitType
}

// NewHierarchicalStrategy creates a new hierarchical rate limiting strategy
func NewHierarchicalStrategy(limitManager *UserOrgLimitManager, limitType LimitType) *HierarchicalStrategy {
	return &HierarchicalStrategy{
		limitManager: limitManager,
		limitType:    limitType,
	}
}

func (s *HierarchicalStrategy) GetBucketKey(request *RateLimitRequest) string {
	return fmt.Sprintf("hierarchical:%s:%s:%s", request.OrgID, request.UserID, s.limitType)
}

func (s *HierarchicalStrategy) GetConfigName(request *RateLimitRequest) string {
	return fmt.Sprintf("hierarchical_%s", s.limitType)
}

func (s *HierarchicalStrategy) GetTokensRequired(request *RateLimitRequest) int64 {
	switch s.limitType {
	case LimitTypeBandwidthPerDay, LimitTypeBandwidthPerMonth:
		return request.RequestSize
	default:
		return 1
	}
}

func (s *HierarchicalStrategy) GetStrategyName() string {
	return fmt.Sprintf("hierarchical_%s", s.limitType)
}

// CheckLimit checks hierarchical limits (org first, then user)
func (s *HierarchicalStrategy) CheckLimit(ctx context.Context, request *RateLimitRequest) (*LimitCheckResult, error) {
	limitRequest := &LimitCheckRequest{
		UserID:      request.UserID,
		OrgID:       request.OrgID,
		LimitType:   s.limitType,
		Amount:      s.GetTokensRequired(request),
		RequestSize: request.RequestSize,
		Timestamp:   request.Timestamp,
	}
	
	return s.limitManager.CheckLimits(ctx, limitRequest)
}

// MultiLayerRateLimiter implements multiple rate limiting layers
type MultiLayerRateLimiter struct {
	manager    *TokenBucketManager
	strategies []RateLimitStrategy
	logger     *logrus.Logger
}

// NewMultiLayerRateLimiter creates a new multi-layer rate limiter
func NewMultiLayerRateLimiter(manager *TokenBucketManager, logger *logrus.Logger) *MultiLayerRateLimiter {
	return &MultiLayerRateLimiter{
		manager:    manager,
		strategies: make([]RateLimitStrategy, 0),
		logger:     logger,
	}
}

// AddStrategy adds a rate limiting strategy
func (ml *MultiLayerRateLimiter) AddStrategy(strategy RateLimitStrategy) {
	ml.strategies = append(ml.strategies, strategy)
	ml.logger.Infof("Added rate limiting strategy: %s", strategy.GetStrategyName())
}

// CheckRateLimit checks all configured strategies
func (ml *MultiLayerRateLimiter) CheckRateLimit(ctx context.Context, request *RateLimitRequest) (*MultiLayerResult, error) {
	result := &MultiLayerResult{
		Request:     request,
		LayerResults: make([]*RateLimitResult, 0),
		Timestamp:   time.Now(),
	}
	
	// Check each strategy
	for _, strategy := range ml.strategies {
		bucketKey := strategy.GetBucketKey(request)
		configName := strategy.GetConfigName(request)
		tokensRequired := strategy.GetTokensRequired(request)
		
		layerResult, err := ml.manager.CheckRateLimit(ctx, bucketKey, tokensRequired, configName)
		if err != nil {
			ml.logger.Errorf("Rate limit check failed for strategy %s: %v", strategy.GetStrategyName(), err)
			continue
		}
		
		// Add strategy info to result
		layerResult.ConfigUsed = fmt.Sprintf("%s:%s", strategy.GetStrategyName(), configName)
		result.LayerResults = append(result.LayerResults, layerResult)
		
		// If any layer denies, the overall result is denied
		if !layerResult.Allowed {
			result.Allowed = false
			result.DeniedBy = strategy.GetStrategyName()
			result.RetryAfter = layerResult.RetryAfter
			break
		}
	}
	
	// If no layer denied, allow the request
	if result.DeniedBy == "" {
		result.Allowed = true
	}
	
	return result, nil
}

// MultiLayerResult represents the result of multi-layer rate limiting
type MultiLayerResult struct {
	Request      *RateLimitRequest   `json:"request"`
	Allowed      bool                `json:"allowed"`
	DeniedBy     string              `json:"denied_by,omitempty"`
	RetryAfter   int64               `json:"retry_after_seconds,omitempty"`
	LayerResults []*RateLimitResult  `json:"layer_results"`
	Timestamp    time.Time           `json:"timestamp"`
}

// GetDeniedLayer returns the layer that denied the request
func (mlr *MultiLayerResult) GetDeniedLayer() *RateLimitResult {
	if mlr.DeniedBy == "" {
		return nil
	}
	
	for _, result := range mlr.LayerResults {
		if strings.Contains(result.ConfigUsed, mlr.DeniedBy) && !result.Allowed {
			return result
		}
	}
	
	return nil
}

// GetMinRetryAfter returns the minimum retry after time from all layers
func (mlr *MultiLayerResult) GetMinRetryAfter() int64 {
	if len(mlr.LayerResults) == 0 {
		return 0
	}
	
	minRetry := mlr.LayerResults[0].RetryAfter
	for _, result := range mlr.LayerResults[1:] {
		if result.RetryAfter > 0 && (minRetry == 0 || result.RetryAfter < minRetry) {
			minRetry = result.RetryAfter
		}
	}
	
	return minRetry
}

// GetSummary returns a summary of the rate limiting result
func (mlr *MultiLayerResult) GetSummary() string {
	if mlr.Allowed {
		return fmt.Sprintf("Allowed by all %d layers", len(mlr.LayerResults))
	}
	
	return fmt.Sprintf("Denied by %s layer (retry after %d seconds)", mlr.DeniedBy, mlr.RetryAfter)
}