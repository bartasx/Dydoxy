package filter

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// API provides REST API endpoints for content filtering
type API struct {
	filter ContentFilter
	logger *logrus.Logger
}

// NewAPI creates a new content filtering API
func NewAPI(filter ContentFilter, logger *logrus.Logger) *API {
	return &API{
		filter: filter,
		logger: logger,
	}
}

// RegisterRoutes registers API routes with Gin router
func (api *API) RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/rules", api.GetRules)
	r.POST("/rules", api.CreateRule)
	r.GET("/rules/:id", api.GetRule)
	r.PUT("/rules/:id", api.UpdateRule)
	r.DELETE("/rules/:id", api.DeleteRule)
	r.POST("/rules/reload", api.ReloadRules)
	r.GET("/stats", api.GetStats)
	r.POST("/test", api.TestFilter)
}

// CreateRuleRequest represents a request to create a new rule
type CreateRuleRequest struct {
	Name        string       `json:"name" binding:"required"`
	Pattern     string       `json:"pattern" binding:"required"`
	Type        RuleType     `json:"type" binding:"required"`
	Action      FilterAction `json:"action" binding:"required"`
	Priority    int          `json:"priority"`
	Enabled     bool         `json:"enabled"`
	Description string       `json:"description"`
}

// UpdateRuleRequest represents a request to update a rule
type UpdateRuleRequest struct {
	Name        string       `json:"name"`
	Pattern     string       `json:"pattern"`
	Type        RuleType     `json:"type"`
	Action      FilterAction `json:"action"`
	Priority    int          `json:"priority"`
	Enabled     *bool        `json:"enabled"`
	Description string       `json:"description"`
}

// TestFilterRequest represents a request to test content filtering
type TestFilterRequest struct {
	URL         string            `json:"url" binding:"required"`
	Domain      string            `json:"domain"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	UserID      string            `json:"user_id"`
	OrgID       string            `json:"org_id"`
}

// GetRules returns all filtering rules
func (api *API) GetRules(c *gin.Context) {
	// Parse query parameters
	ruleTypeStr := c.Query("type")
	var ruleType *RuleType
	if ruleTypeStr != "" {
		if typeInt, err := strconv.Atoi(ruleTypeStr); err == nil {
			rt := RuleType(typeInt)
			ruleType = &rt
		}
	}
	
	var rules []*FilterRule
	var err error
	
	if ruleType != nil {
		rules, err = api.filter.GetRulesByType(c.Request.Context(), *ruleType)
	} else {
		rules, err = api.filter.GetRules(c.Request.Context())
	}
	
	if err != nil {
		api.logger.Errorf("Failed to get rules: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rules"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// CreateRule creates a new filtering rule
func (api *API) CreateRule(c *gin.Context) {
	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	rule := &FilterRule{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Pattern:     req.Pattern,
		Type:        req.Type,
		Action:      req.Action,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	if err := api.filter.AddRule(c.Request.Context(), rule); err != nil {
		api.logger.Errorf("Failed to create rule: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Rule created successfully",
		"rule":    rule,
	})
}

// GetRule returns a specific rule by ID
func (api *API) GetRule(c *gin.Context) {
	ruleID := c.Param("id")
	
	rules, err := api.filter.GetRules(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get rules: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rules"})
		return
	}
	
	for _, rule := range rules {
		if rule.ID == ruleID {
			c.JSON(http.StatusOK, gin.H{"rule": rule})
			return
		}
	}
	
	c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
}

// UpdateRule updates an existing filtering rule
func (api *API) UpdateRule(c *gin.Context) {
	ruleID := c.Param("id")
	
	var req UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Get existing rule
	rules, err := api.filter.GetRules(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get rules: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rules"})
		return
	}
	
	var existingRule *FilterRule
	for _, rule := range rules {
		if rule.ID == ruleID {
			existingRule = rule
			break
		}
	}
	
	if existingRule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}
	
	// Update fields
	if req.Name != "" {
		existingRule.Name = req.Name
	}
	if req.Pattern != "" {
		existingRule.Pattern = req.Pattern
	}
	if req.Type != 0 {
		existingRule.Type = req.Type
	}
	if req.Action != 0 {
		existingRule.Action = req.Action
	}
	if req.Priority != 0 {
		existingRule.Priority = req.Priority
	}
	if req.Enabled != nil {
		existingRule.Enabled = *req.Enabled
	}
	if req.Description != "" {
		existingRule.Description = req.Description
	}
	
	existingRule.UpdatedAt = time.Now()
	
	if err := api.filter.UpdateRule(c.Request.Context(), existingRule); err != nil {
		api.logger.Errorf("Failed to update rule: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Rule updated successfully",
		"rule":    existingRule,
	})
}

// DeleteRule deletes a filtering rule
func (api *API) DeleteRule(c *gin.Context) {
	ruleID := c.Param("id")
	
	if err := api.filter.RemoveRule(c.Request.Context(), ruleID); err != nil {
		api.logger.Errorf("Failed to delete rule: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// ReloadRules reloads rules from storage
func (api *API) ReloadRules(c *gin.Context) {
	if err := api.filter.ReloadRules(c.Request.Context()); err != nil {
		api.logger.Errorf("Failed to reload rules: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload rules"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Rules reloaded successfully"})
}

// GetStats returns filtering statistics
func (api *API) GetStats(c *gin.Context) {
	stats, err := api.filter.GetStats(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// TestFilter tests content filtering against a request
func (api *API) TestFilter(c *gin.Context) {
	var req TestFilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Create content request
	contentReq := &ContentRequest{
		URL:         req.URL,
		Domain:      req.Domain,
		Method:      req.Method,
		Headers:     req.Headers,
		ContentType: req.ContentType,
		UserID:      req.UserID,
		OrgID:       req.OrgID,
	}
	
	// Apply filtering
	result, err := api.filter.Filter(c.Request.Context(), contentReq)
	if err != nil {
		api.logger.Errorf("Failed to test filter: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test filter"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"request": contentReq,
		"result":  result,
	})
}