package filter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Middleware provides HTTP middleware for content filtering
type Middleware struct {
	filter ContentFilter
	logger *logrus.Logger
}

// NewMiddleware creates a new content filtering middleware
func NewMiddleware(filter ContentFilter, logger *logrus.Logger) *Middleware {
	return &Middleware{
		filter: filter,
		logger: logger,
	}
}

// GinMiddleware returns a Gin middleware function
func (m *Middleware) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create content request from HTTP request
		request := m.createContentRequest(c)
		
		// Apply content filtering
		result, err := m.filter.Filter(c.Request.Context(), request)
		if err != nil {
			m.logger.Errorf("Content filtering error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Content filtering failed",
			})
			c.Abort()
			return
		}
		
		// Handle filtering result
		if !result.Allowed {
			m.logger.Warnf("Content blocked - URL: %s, User: %s, Rule: %s", 
				request.URL, request.UserID, result.MatchedRule.Name)
			
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "Content blocked by security policy",
				"reason": result.Reason,
				"rule":   result.MatchedRule.Name,
			})
			c.Abort()
			return
		}
		
		// Add filtering result to context for downstream handlers
		c.Set("filter_result", result)
		
		// Continue to next handler
		c.Next()
	}
}

// HTTPMiddleware returns a standard HTTP middleware function
func (m *Middleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create content request from HTTP request
		request := m.createContentRequestFromHTTP(r)
		
		// Apply content filtering
		result, err := m.filter.Filter(r.Context(), request)
		if err != nil {
			m.logger.Errorf("Content filtering error: %v", err)
			http.Error(w, "Content filtering failed", http.StatusInternalServerError)
			return
		}
		
		// Handle filtering result
		if !result.Allowed {
			m.logger.Warnf("Content blocked - URL: %s, User: %s, Rule: %s", 
				request.URL, request.UserID, result.MatchedRule.Name)
			
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"Content blocked by security policy","reason":"%s","rule":"%s"}`, 
				result.Reason, result.MatchedRule.Name)
			return
		}
		
		// Add filtering result to context for downstream handlers
		ctx := context.WithValue(r.Context(), "filter_result", result)
		r = r.WithContext(ctx)
		
		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// createContentRequest creates a ContentRequest from Gin context
func (m *Middleware) createContentRequest(c *gin.Context) *ContentRequest {
	// Extract domain from URL
	parsedURL, _ := url.Parse(c.Request.URL.String())
	domain := parsedURL.Host
	if domain == "" {
		domain = c.Request.Host
	}
	
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
	
	return &ContentRequest{
		URL:         c.Request.URL.String(),
		Domain:      domain,
		Method:      c.Request.Method,
		Headers:     headers,
		ContentType: c.Request.Header.Get("Content-Type"),
		UserID:      userID,
		OrgID:       orgID,
	}
}

// createContentRequestFromHTTP creates a ContentRequest from HTTP request
func (m *Middleware) createContentRequestFromHTTP(r *http.Request) *ContentRequest {
	// Extract domain from URL
	parsedURL, _ := url.Parse(r.URL.String())
	domain := parsedURL.Host
	if domain == "" {
		domain = r.Host
	}
	
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
	
	return &ContentRequest{
		URL:         r.URL.String(),
		Domain:      domain,
		Method:      r.Method,
		Headers:     headers,
		ContentType: r.Header.Get("Content-Type"),
		UserID:      userID,
		OrgID:       orgID,
	}
}

// extractUserID extracts user ID from Gin context
func (m *Middleware) extractUserID(c *gin.Context) string {
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
func (m *Middleware) extractOrgID(c *gin.Context) string {
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
func (m *Middleware) extractUserIDFromHTTP(r *http.Request) string {
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
func (m *Middleware) extractOrgIDFromHTTP(r *http.Request) string {
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

// ProxyFilterFunc returns a function that can be used with HTTP proxies
func (m *Middleware) ProxyFilterFunc() func(*http.Request) (*FilterResult, error) {
	return func(r *http.Request) (*FilterResult, error) {
		request := m.createContentRequestFromHTTP(r)
		return m.filter.Filter(r.Context(), request)
	}
}