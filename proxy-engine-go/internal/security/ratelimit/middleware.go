package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RateLimitMiddleware provides HTTP middleware for rate limiting
type RateLimitMiddleware struct {
	limiter *MultiLayerRateLimiter
	logger  *logrus.Logger
	config  *MiddlewareConfig
}

// MiddlewareConfig represents configuration for rate limiting middleware
type MiddlewareConfig struct {
	// SkipSuccessfulRequests skips rate limiting for successful requests
	SkipSuccessfulRequests bool
	
	// SkipFailedRequests skips rate limiting for failed requests
	SkipFailedRequests bool
	
	// KeyGenerator generates custom keys for rate limiting
	KeyGenerator func(*gin.Context) string
	
	// OnRateLimitExceeded is called when rate limit is exceeded
	OnRateLimitExceeded func(*gin.Context, *MultiLayerResult)
	
	// Headers to include in rate limit response
	IncludeHeaders bool
	
	// Custom error message
	ErrorMessage string
	
	// Custom error status code
	ErrorStatusCode int
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		SkipSuccessfulRequests: false,
		SkipFailedRequests:     false,
		IncludeHeaders:         true,
		ErrorMessage:           "Rate limit exceeded",
		ErrorStatusCode:        http.StatusTooManyRequests,
	}
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(limiter *MultiLayerRateLimiter, logger *logrus.Logger, config *MiddlewareConfig) *RateLimitMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}
	
	return &RateLimitMiddleware{
		limiter: limiter,
		logger:  logger,
		config:  config,
	}
}

// GinMiddleware returns a Gin middleware function
func (m *RateLimitMiddleware) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create rate limit request
		request := m.createRateLimitRequest(c)
		
		// Check rate limit
		result, err := m.limiter.CheckRateLimit(c.Request.Context(), request)
		if err != nil {
			m.logger.Errorf("Rate limit check failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Rate limit check failed",
			})
			c.Abort()
			return
		}
		
		// Add rate limit headers
		if m.config.IncludeHeaders {
			m.addRateLimitHeaders(c, result)
		}
		
		// Check if request is allowed
		if !result.Allowed {
			m.handleRateLimitExceeded(c, result)
			return
		}
		
		// Store result in context for downstream handlers
		c.Set("rate_limit_result", result)
		
		// Continue to next handler
		c.Next()
	}
}

// HTTPMiddleware returns a standard HTTP middleware function
func (m *RateLimitMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create rate limit request
		request := m.createRateLimitRequestFromHTTP(r)
		
		// Check rate limit
		result, err := m.limiter.CheckRateLimit(r.Context(), request)
		if err != nil {
			m.logger.Errorf("Rate limit check failed: %v", err)
			http.Error(w, "Rate limit check failed", http.StatusInternalServerError)
			return
		}
		
		// Add rate limit headers
		if m.config.IncludeHeaders {
			m.addRateLimitHeadersHTTP(w, result)
		}
		
		// Check if request is allowed
		if !result.Allowed {
			m.handleRateLimitExceededHTTP(w, r, result)
			return
		}
		
		// Add result to context for downstream handlers
		ctx := context.WithValue(r.Context(), "rate_limit_result", result)
		r = r.WithContext(ctx)
		
		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// createRateLimitRequest creates a RateLimitRequest from Gin context
func (m *RateLimitMiddleware) createRateLimitRequest(c *gin.Context) *RateLimitRequest {
	// Extract headers
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	
	// Get user and org IDs from context or headers
	userID := m.extractUserID(c)
	orgID := m.extractOrgID(c)
	
	// Get client IP
	clientIP := c.ClientIP()
	
	// Get request size
	requestSize := c.Request.ContentLength
	if requestSize < 0 {
		requestSize = 0
	}
	
	// Create metadata
	metadata := make(map[string]interface{})
	
	// Add tier information if available
	if tier, exists := c.Get("user_tier"); exists {
		metadata["tier"] = tier
	}
	
	// Add custom key if generator is provided
	if m.config.KeyGenerator != nil {
		metadata["custom_key"] = m.config.KeyGenerator(c)
	}
	
	return &RateLimitRequest{
		UserID:      userID,
		OrgID:       orgID,
		IP:          clientIP,
		Endpoint:    c.Request.URL.Path,
		Method:      c.Request.Method,
		UserAgent:   c.Request.UserAgent(),
		Headers:     headers,
		RequestSize: requestSize,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}
}

// createRateLimitRequestFromHTTP creates a RateLimitRequest from HTTP request
func (m *RateLimitMiddleware) createRateLimitRequestFromHTTP(r *http.Request) *RateLimitRequest {
	// Extract headers
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	
	// Get user and org IDs from context or headers
	userID := m.extractUserIDFromHTTP(r)
	orgID := m.extractOrgIDFromHTTP(r)
	
	// Get client IP
	clientIP := m.getClientIP(r)
	
	// Get request size
	requestSize := r.ContentLength
	if requestSize < 0 {
		requestSize = 0
	}
	
	// Create metadata
	metadata := make(map[string]interface{})
	
	// Add tier information if available
	if tier := r.Context().Value("user_tier"); tier != nil {
		metadata["tier"] = tier
	}
	
	return &RateLimitRequest{
		UserID:      userID,
		OrgID:       orgID,
		IP:          clientIP,
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		UserAgent:   r.UserAgent(),
		Headers:     headers,
		RequestSize: requestSize,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}
}

// extractUserID extracts user ID from Gin context
func (m *RateLimitMiddleware) extractUserID(c *gin.Context) string {
	// Try to get from context (set by auth middleware)
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	
	// Try to get from headers
	if userID := c.GetHeader("X-User-ID"); userID != "" {
		return userID
	}
	
	// Try to get from query parameters
	if userID := c.Query("user_id"); userID != "" {
		return userID
	}
	
	return "anonymous"
}

// extractOrgID extracts organization ID from Gin context
func (m *RateLimitMiddleware) extractOrgID(c *gin.Context) string {
	// Try to get from context (set by auth middleware)
	if orgID, exists := c.Get("org_id"); exists {
		if id, ok := orgID.(string); ok {
			return id
		}
	}
	
	// Try to get from headers
	if orgID := c.GetHeader("X-Org-ID"); orgID != "" {
		return orgID
	}
	
	return "default"
}

// extractUserIDFromHTTP extracts user ID from HTTP request
func (m *RateLimitMiddleware) extractUserIDFromHTTP(r *http.Request) string {
	// Try to get from context
	if userID := r.Context().Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	
	// Try to get from headers
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	
	// Try to get from query parameters
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		return userID
	}
	
	return "anonymous"
}

// extractOrgIDFromHTTP extracts organization ID from HTTP request
func (m *RateLimitMiddleware) extractOrgIDFromHTTP(r *http.Request) string {
	// Try to get from context
	if orgID := r.Context().Value("org_id"); orgID != nil {
		if id, ok := orgID.(string); ok {
			return id
		}
	}
	
	// Try to get from headers
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		return orgID
	}
	
	return "default"
}

// getClientIP extracts client IP from HTTP request
func (m *RateLimitMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Use remote address
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	
	return ip
}

// addRateLimitHeaders adds rate limit headers to Gin response
func (m *RateLimitMiddleware) addRateLimitHeaders(c *gin.Context, result *MultiLayerResult) {
	if len(result.LayerResults) == 0 {
		return
	}
	
	// Use the most restrictive layer for headers
	var mostRestrictive *RateLimitResult
	for _, layerResult := range result.LayerResults {
		if mostRestrictive == nil || layerResult.TokensLeft < mostRestrictive.TokensLeft {
			mostRestrictive = layerResult
		}
	}
	
	if mostRestrictive != nil {
		c.Header("X-RateLimit-Limit", strconv.FormatInt(mostRestrictive.TokensLeft+1, 10)) // Approximate
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(mostRestrictive.TokensLeft, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(mostRestrictive.ResetTime.Unix(), 10))
		
		if !result.Allowed {
			c.Header("Retry-After", strconv.FormatInt(result.RetryAfter, 10))
		}
	}
}

// addRateLimitHeadersHTTP adds rate limit headers to HTTP response
func (m *RateLimitMiddleware) addRateLimitHeadersHTTP(w http.ResponseWriter, result *MultiLayerResult) {
	if len(result.LayerResults) == 0 {
		return
	}
	
	// Use the most restrictive layer for headers
	var mostRestrictive *RateLimitResult
	for _, layerResult := range result.LayerResults {
		if mostRestrictive == nil || layerResult.TokensLeft < mostRestrictive.TokensLeft {
			mostRestrictive = layerResult
		}
	}
	
	if mostRestrictive != nil {
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(mostRestrictive.TokensLeft+1, 10)) // Approximate
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(mostRestrictive.TokensLeft, 10))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(mostRestrictive.ResetTime.Unix(), 10))
		
		if !result.Allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(result.RetryAfter, 10))
		}
	}
}

// handleRateLimitExceeded handles rate limit exceeded for Gin
func (m *RateLimitMiddleware) handleRateLimitExceeded(c *gin.Context, result *MultiLayerResult) {
	// Call custom handler if provided
	if m.config.OnRateLimitExceeded != nil {
		m.config.OnRateLimitExceeded(c, result)
		return
	}
	
	// Log the rate limit violation
	m.logger.Warnf("Rate limit exceeded - User: %s, IP: %s, Endpoint: %s, Denied by: %s", 
		result.Request.UserID, result.Request.IP, result.Request.Endpoint, result.DeniedBy)
	
	// Return error response
	c.JSON(m.config.ErrorStatusCode, gin.H{
		"error":       m.config.ErrorMessage,
		"denied_by":   result.DeniedBy,
		"retry_after": result.RetryAfter,
		"summary":     result.GetSummary(),
	})
	c.Abort()
}

// handleRateLimitExceededHTTP handles rate limit exceeded for HTTP
func (m *RateLimitMiddleware) handleRateLimitExceededHTTP(w http.ResponseWriter, r *http.Request, result *MultiLayerResult) {
	// Log the rate limit violation
	m.logger.Warnf("Rate limit exceeded - User: %s, IP: %s, Endpoint: %s, Denied by: %s", 
		result.Request.UserID, result.Request.IP, result.Request.Endpoint, result.DeniedBy)
	
	// Set content type
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(m.config.ErrorStatusCode)
	
	// Write error response
	errorResponse := fmt.Sprintf(`{
		"error": "%s",
		"denied_by": "%s",
		"retry_after": %d,
		"summary": "%s"
	}`, m.config.ErrorMessage, result.DeniedBy, result.RetryAfter, result.GetSummary())
	
	w.Write([]byte(errorResponse))
}

// ProxyRateLimitFunc returns a function that can be used with HTTP proxies
func (m *RateLimitMiddleware) ProxyRateLimitFunc() func(*http.Request) (*MultiLayerResult, error) {
	return func(r *http.Request) (*MultiLayerResult, error) {
		request := m.createRateLimitRequestFromHTTP(r)
		return m.limiter.CheckRateLimit(r.Context(), request)
	}
}