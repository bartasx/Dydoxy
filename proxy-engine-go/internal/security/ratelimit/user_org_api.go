package ratelimit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// UserOrgLimitAPI provides REST API endpoints for user/org limit management
type UserOrgLimitAPI struct {
	manager *UserOrgLimitManager
	logger  *logrus.Logger
}

// NewUserOrgLimitAPI creates a new user/org limit API
func NewUserOrgLimitAPI(manager *UserOrgLimitManager, logger *logrus.Logger) *UserOrgLimitAPI {
	return &UserOrgLimitAPI{
		manager: manager,
		logger:  logger,
	}
}

// RegisterRoutes registers API routes with Gin router
func (api *UserOrgLimitAPI) RegisterRoutes(r *gin.RouterGroup) {
	// User limits
	r.GET("/users", api.GetUserLimits)
	r.POST("/users", api.CreateUserLimits)
	r.GET("/users/:userId", api.GetUserLimit)
	r.PUT("/users/:userId", api.UpdateUserLimits)
	r.DELETE("/users/:userId", api.DeleteUserLimits)
	r.GET("/users/:userId/usage", api.GetUserUsage)
	r.POST("/users/:userId/usage/reset", api.ResetUserUsage)
	
	// Organization limits
	r.GET("/orgs", api.GetOrgLimits)
	r.POST("/orgs", api.CreateOrgLimits)
	r.GET("/orgs/:orgId", api.GetOrgLimit)
	r.PUT("/orgs/:orgId", api.UpdateOrgLimits)
	r.DELETE("/orgs/:orgId", api.DeleteOrgLimits)
	r.GET("/orgs/:orgId/usage", api.GetOrgUsage)
	r.POST("/orgs/:orgId/usage/reset", api.ResetOrgUsage)
	
	// Limit checking
	r.POST("/check", api.CheckLimits)
	r.POST("/increment", api.IncrementUsage)
	
	// Default tiers and plans
	r.GET("/tiers", api.GetDefaultTiers)
	r.GET("/plans", api.GetDefaultPlans)
	
	// Statistics
	r.GET("/stats", api.GetStats)
	r.GET("/usage-patterns", api.GetUsagePatterns)
}

// CreateUserLimitsRequest represents a request to create user limits
type CreateUserLimitsRequest struct {
	UserID           string                 `json:"user_id" binding:"required"`
	OrgID            string                 `json:"org_id" binding:"required"`
	Tier             string                 `json:"tier"`
	RequestsPerHour  int64                  `json:"requests_per_hour,omitempty"`
	RequestsPerDay   int64                  `json:"requests_per_day,omitempty"`
	RequestsPerMonth int64                  `json:"requests_per_month,omitempty"`
	BandwidthPerDay  int64                  `json:"bandwidth_per_day,omitempty"`
	BandwidthPerMonth int64                 `json:"bandwidth_per_month,omitempty"`
	ConcurrentConns  int64                  `json:"concurrent_connections,omitempty"`
	CustomLimits     map[string]int64       `json:"custom_limits,omitempty"`
	Overrides        map[string]interface{} `json:"overrides,omitempty"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	Enabled          bool                   `json:"enabled"`
}

// UpdateUserLimitsRequest represents a request to update user limits
type UpdateUserLimitsRequest struct {
	Tier             string                 `json:"tier,omitempty"`
	RequestsPerHour  *int64                 `json:"requests_per_hour,omitempty"`
	RequestsPerDay   *int64                 `json:"requests_per_day,omitempty"`
	RequestsPerMonth *int64                 `json:"requests_per_month,omitempty"`
	BandwidthPerDay  *int64                 `json:"bandwidth_per_day,omitempty"`
	BandwidthPerMonth *int64                `json:"bandwidth_per_month,omitempty"`
	ConcurrentConns  *int64                 `json:"concurrent_connections,omitempty"`
	CustomLimits     map[string]int64       `json:"custom_limits,omitempty"`
	Overrides        map[string]interface{} `json:"overrides,omitempty"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	Enabled          *bool                  `json:"enabled,omitempty"`
}

// CreateOrgLimitsRequest represents a request to create org limits
type CreateOrgLimitsRequest struct {
	OrgID            string           `json:"org_id" binding:"required"`
	Plan             string           `json:"plan"`
	RequestsPerHour  int64            `json:"requests_per_hour,omitempty"`
	RequestsPerDay   int64            `json:"requests_per_day,omitempty"`
	RequestsPerMonth int64            `json:"requests_per_month,omitempty"`
	BandwidthPerDay  int64            `json:"bandwidth_per_day,omitempty"`
	BandwidthPerMonth int64           `json:"bandwidth_per_month,omitempty"`
	MaxUsers         int64            `json:"max_users,omitempty"`
	MaxConcurrentConns int64          `json:"max_concurrent_connections,omitempty"`
	CustomLimits     map[string]int64 `json:"custom_limits,omitempty"`
	Features         []string         `json:"features,omitempty"`
	Enabled          bool             `json:"enabled"`
}

// UpdateOrgLimitsRequest represents a request to update org limits
type UpdateOrgLimitsRequest struct {
	Plan             string           `json:"plan,omitempty"`
	RequestsPerHour  *int64           `json:"requests_per_hour,omitempty"`
	RequestsPerDay   *int64           `json:"requests_per_day,omitempty"`
	RequestsPerMonth *int64           `json:"requests_per_month,omitempty"`
	BandwidthPerDay  *int64           `json:"bandwidth_per_day,omitempty"`
	BandwidthPerMonth *int64          `json:"bandwidth_per_month,omitempty"`
	MaxUsers         *int64           `json:"max_users,omitempty"`
	MaxConcurrentConns *int64         `json:"max_concurrent_connections,omitempty"`
	CustomLimits     map[string]int64 `json:"custom_limits,omitempty"`
	Features         []string         `json:"features,omitempty"`
	Enabled          *bool            `json:"enabled,omitempty"`
}

// CheckLimitsRequest represents a request to check limits
type CheckLimitsRequest struct {
	UserID      string    `json:"user_id" binding:"required"`
	OrgID       string    `json:"org_id" binding:"required"`
	LimitType   LimitType `json:"limit_type" binding:"required"`
	Amount      int64     `json:"amount,omitempty"`
	RequestSize int64     `json:"request_size,omitempty"`
}

// IncrementUsageRequest represents a request to increment usage
type IncrementUsageRequest struct {
	UserID    string    `json:"user_id" binding:"required"`
	OrgID     string    `json:"org_id" binding:"required"`
	LimitType LimitType `json:"limit_type" binding:"required"`
	Amount    int64     `json:"amount" binding:"required"`
}

// GetUserLimits returns all user limits
func (api *UserOrgLimitAPI) GetUserLimits(c *gin.Context) {
	orgID := c.Query("org_id")
	
	limits, err := api.manager.storage.ListUserLimits(c.Request.Context(), orgID)
	if err != nil {
		api.logger.Errorf("Failed to get user limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"limits": limits,
		"count":  len(limits),
	})
}

// CreateUserLimits creates new user limits
func (api *UserOrgLimitAPI) CreateUserLimits(c *gin.Context) {
	var req CreateUserLimitsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	limits := &UserLimits{
		UserID:           req.UserID,
		OrgID:            req.OrgID,
		Tier:             req.Tier,
		RequestsPerHour:  req.RequestsPerHour,
		RequestsPerDay:   req.RequestsPerDay,
		RequestsPerMonth: req.RequestsPerMonth,
		BandwidthPerDay:  req.BandwidthPerDay,
		BandwidthPerMonth: req.BandwidthPerMonth,
		ConcurrentConns:  req.ConcurrentConns,
		CustomLimits:     req.CustomLimits,
		Overrides:        req.Overrides,
		ExpiresAt:        req.ExpiresAt,
		Enabled:          req.Enabled,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	
	if err := api.manager.SetUserLimits(c.Request.Context(), limits); err != nil {
		api.logger.Errorf("Failed to create user limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user limits"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "User limits created successfully",
		"limits":  limits,
	})
}

// GetUserLimit returns specific user limits
func (api *UserOrgLimitAPI) GetUserLimit(c *gin.Context) {
	userID := c.Param("userId")
	
	limits, err := api.manager.GetUserLimits(c.Request.Context(), userID)
	if err != nil {
		api.logger.Errorf("Failed to get user limit: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User limits not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"limits": limits})
}

// UpdateUserLimits updates existing user limits
func (api *UserOrgLimitAPI) UpdateUserLimits(c *gin.Context) {
	userID := c.Param("userId")
	
	var req UpdateUserLimitsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Get existing limits
	limits, err := api.manager.GetUserLimits(c.Request.Context(), userID)
	if err != nil {
		api.logger.Errorf("Failed to get user limits: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User limits not found"})
		return
	}
	
	// Update fields
	if req.Tier != "" {
		limits.Tier = req.Tier
	}
	if req.RequestsPerHour != nil {
		limits.RequestsPerHour = *req.RequestsPerHour
	}
	if req.RequestsPerDay != nil {
		limits.RequestsPerDay = *req.RequestsPerDay
	}
	if req.RequestsPerMonth != nil {
		limits.RequestsPerMonth = *req.RequestsPerMonth
	}
	if req.BandwidthPerDay != nil {
		limits.BandwidthPerDay = *req.BandwidthPerDay
	}
	if req.BandwidthPerMonth != nil {
		limits.BandwidthPerMonth = *req.BandwidthPerMonth
	}
	if req.ConcurrentConns != nil {
		limits.ConcurrentConns = *req.ConcurrentConns
	}
	if req.CustomLimits != nil {
		limits.CustomLimits = req.CustomLimits
	}
	if req.Overrides != nil {
		limits.Overrides = req.Overrides
	}
	if req.ExpiresAt != nil {
		limits.ExpiresAt = req.ExpiresAt
	}
	if req.Enabled != nil {
		limits.Enabled = *req.Enabled
	}
	
	if err := api.manager.SetUserLimits(c.Request.Context(), limits); err != nil {
		api.logger.Errorf("Failed to update user limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "User limits updated successfully",
		"limits":  limits,
	})
}

// DeleteUserLimits deletes user limits
func (api *UserOrgLimitAPI) DeleteUserLimits(c *gin.Context) {
	userID := c.Param("userId")
	
	if err := api.manager.storage.DeleteUserLimits(c.Request.Context(), userID); err != nil {
		api.logger.Errorf("Failed to delete user limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "User limits deleted successfully"})
}

// GetOrgLimits returns all organization limits
func (api *UserOrgLimitAPI) GetOrgLimits(c *gin.Context) {
	limits, err := api.manager.storage.ListOrgLimits(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get org limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get org limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"limits": limits,
		"count":  len(limits),
	})
}

// CreateOrgLimits creates new organization limits
func (api *UserOrgLimitAPI) CreateOrgLimits(c *gin.Context) {
	var req CreateOrgLimitsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	limits := &OrgLimits{
		OrgID:            req.OrgID,
		Plan:             req.Plan,
		RequestsPerHour:  req.RequestsPerHour,
		RequestsPerDay:   req.RequestsPerDay,
		RequestsPerMonth: req.RequestsPerMonth,
		BandwidthPerDay:  req.BandwidthPerDay,
		BandwidthPerMonth: req.BandwidthPerMonth,
		MaxUsers:         req.MaxUsers,
		MaxConcurrentConns: req.MaxConcurrentConns,
		CustomLimits:     req.CustomLimits,
		Features:         req.Features,
		Enabled:          req.Enabled,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	
	if err := api.manager.SetOrgLimits(c.Request.Context(), limits); err != nil {
		api.logger.Errorf("Failed to create org limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create org limits"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Organization limits created successfully",
		"limits":  limits,
	})
}

// GetOrgLimit returns specific organization limits
func (api *UserOrgLimitAPI) GetOrgLimit(c *gin.Context) {
	orgID := c.Param("orgId")
	
	limits, err := api.manager.GetOrgLimits(c.Request.Context(), orgID)
	if err != nil {
		api.logger.Errorf("Failed to get org limit: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization limits not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"limits": limits})
}

// UpdateOrgLimits updates existing organization limits
func (api *UserOrgLimitAPI) UpdateOrgLimits(c *gin.Context) {
	orgID := c.Param("orgId")
	
	var req UpdateOrgLimitsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Get existing limits
	limits, err := api.manager.GetOrgLimits(c.Request.Context(), orgID)
	if err != nil {
		api.logger.Errorf("Failed to get org limits: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization limits not found"})
		return
	}
	
	// Update fields
	if req.Plan != "" {
		limits.Plan = req.Plan
	}
	if req.RequestsPerHour != nil {
		limits.RequestsPerHour = *req.RequestsPerHour
	}
	if req.RequestsPerDay != nil {
		limits.RequestsPerDay = *req.RequestsPerDay
	}
	if req.RequestsPerMonth != nil {
		limits.RequestsPerMonth = *req.RequestsPerMonth
	}
	if req.BandwidthPerDay != nil {
		limits.BandwidthPerDay = *req.BandwidthPerDay
	}
	if req.BandwidthPerMonth != nil {
		limits.BandwidthPerMonth = *req.BandwidthPerMonth
	}
	if req.MaxUsers != nil {
		limits.MaxUsers = *req.MaxUsers
	}
	if req.MaxConcurrentConns != nil {
		limits.MaxConcurrentConns = *req.MaxConcurrentConns
	}
	if req.CustomLimits != nil {
		limits.CustomLimits = req.CustomLimits
	}
	if req.Features != nil {
		limits.Features = req.Features
	}
	if req.Enabled != nil {
		limits.Enabled = *req.Enabled
	}
	
	if err := api.manager.SetOrgLimits(c.Request.Context(), limits); err != nil {
		api.logger.Errorf("Failed to update org limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update org limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Organization limits updated successfully",
		"limits":  limits,
	})
}

// DeleteOrgLimits deletes organization limits
func (api *UserOrgLimitAPI) DeleteOrgLimits(c *gin.Context) {
	orgID := c.Param("orgId")
	
	if err := api.manager.storage.DeleteOrgLimits(c.Request.Context(), orgID); err != nil {
		api.logger.Errorf("Failed to delete org limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete org limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Organization limits deleted successfully"})
}

// CheckLimits checks user/org limits
func (api *UserOrgLimitAPI) CheckLimits(c *gin.Context) {
	var req CheckLimitsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if req.Amount <= 0 {
		req.Amount = 1
	}
	
	limitRequest := &LimitCheckRequest{
		UserID:      req.UserID,
		OrgID:       req.OrgID,
		LimitType:   req.LimitType,
		Amount:      req.Amount,
		RequestSize: req.RequestSize,
		Timestamp:   time.Now(),
	}
	
	result, err := api.manager.CheckLimits(c.Request.Context(), limitRequest)
	if err != nil {
		api.logger.Errorf("Failed to check limits: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check limits"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"request": limitRequest,
		"result":  result,
	})
}

// IncrementUsage increments usage counters
func (api *UserOrgLimitAPI) IncrementUsage(c *gin.Context) {
	var req IncrementUsageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if err := api.manager.IncrementUsage(c.Request.Context(), req.UserID, req.OrgID, req.LimitType, req.Amount); err != nil {
		api.logger.Errorf("Failed to increment usage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to increment usage"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Usage incremented successfully"})
}

// GetDefaultTiers returns default user tiers
func (api *UserOrgLimitAPI) GetDefaultTiers(c *gin.Context) {
	tiers := api.manager.GetDefaultTiers()
	c.JSON(http.StatusOK, gin.H{"tiers": tiers})
}

// GetDefaultPlans returns default organization plans
func (api *UserOrgLimitAPI) GetDefaultPlans(c *gin.Context) {
	plans := api.manager.GetDefaultPlans()
	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

// GetStats returns user/org limit statistics
func (api *UserOrgLimitAPI) GetStats(c *gin.Context) {
	stats, err := api.manager.GetStats(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// GetUserUsage returns usage for a specific user
func (api *UserOrgLimitAPI) GetUserUsage(c *gin.Context) {
	userID := c.Param("userId")
	orgID := c.Query("org_id")
	limitType := LimitType(c.Query("limit_type"))
	period := LimitPeriod(c.Query("period"))
	
	if limitType == "" {
		limitType = LimitTypeRequestsPerDay
	}
	if period == "" {
		period = PeriodDay
	}
	
	usage, err := api.manager.storage.GetUsage(c.Request.Context(), userID, orgID, limitType, period)
	if err != nil {
		api.logger.Errorf("Failed to get user usage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user usage"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"org_id":     orgID,
		"limit_type": limitType,
		"period":     period,
		"usage":      usage,
	})
}

// GetOrgUsage returns usage for a specific organization
func (api *UserOrgLimitAPI) GetOrgUsage(c *gin.Context) {
	orgID := c.Param("orgId")
	limitType := LimitType(c.Query("limit_type"))
	period := LimitPeriod(c.Query("period"))
	
	if limitType == "" {
		limitType = LimitTypeRequestsPerDay
	}
	if period == "" {
		period = PeriodDay
	}
	
	usage, err := api.manager.storage.GetUsage(c.Request.Context(), "", orgID, limitType, period)
	if err != nil {
		api.logger.Errorf("Failed to get org usage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get org usage"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"org_id":     orgID,
		"limit_type": limitType,
		"period":     period,
		"usage":      usage,
	})
}

// ResetUserUsage resets usage for a specific user
func (api *UserOrgLimitAPI) ResetUserUsage(c *gin.Context) {
	userID := c.Param("userId")
	orgID := c.Query("org_id")
	limitType := LimitType(c.Query("limit_type"))
	period := LimitPeriod(c.Query("period"))
	
	if err := api.manager.storage.ResetUsage(c.Request.Context(), userID, orgID, limitType, period); err != nil {
		api.logger.Errorf("Failed to reset user usage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset user usage"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "User usage reset successfully"})
}

// ResetOrgUsage resets usage for a specific organization
func (api *UserOrgLimitAPI) ResetOrgUsage(c *gin.Context) {
	orgID := c.Param("orgId")
	limitType := LimitType(c.Query("limit_type"))
	period := LimitPeriod(c.Query("period"))
	
	if err := api.manager.storage.ResetUsage(c.Request.Context(), "", orgID, limitType, period); err != nil {
		api.logger.Errorf("Failed to reset org usage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset org usage"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Organization usage reset successfully"})
}

// GetUsagePatterns returns usage patterns for analysis
func (api *UserOrgLimitAPI) GetUsagePatterns(c *gin.Context) {
	userID := c.Query("user_id")
	orgID := c.Query("org_id")
	limitType := LimitType(c.Query("limit_type"))
	daysStr := c.Query("days")
	
	days := 30 // Default to 30 days
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil && parsed > 0 {
			days = parsed
		}
	}
	
	if limitType == "" {
		limitType = LimitTypeRequestsPerDay
	}
	
	// This would need to be implemented in the storage
	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"org_id":     orgID,
		"limit_type": limitType,
		"days":       days,
		"patterns":   map[string]int64{},
		"message":    "Usage patterns analysis not yet implemented",
	})
}