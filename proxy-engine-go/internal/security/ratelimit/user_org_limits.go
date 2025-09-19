package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// UserLimits represents rate limits for a specific user
type UserLimits struct {
	UserID           string                 `json:"user_id"`
	OrgID            string                 `json:"org_id"`
	Tier             string                 `json:"tier"`
	RequestsPerHour  int64                  `json:"requests_per_hour"`
	RequestsPerDay   int64                  `json:"requests_per_day"`
	RequestsPerMonth int64                  `json:"requests_per_month"`
	BandwidthPerDay  int64                  `json:"bandwidth_per_day"`  // bytes
	BandwidthPerMonth int64                 `json:"bandwidth_per_month"` // bytes
	ConcurrentConns  int64                  `json:"concurrent_connections"`
	CustomLimits     map[string]int64       `json:"custom_limits,omitempty"`
	Overrides        map[string]interface{} `json:"overrides,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	Enabled          bool                   `json:"enabled"`
}

// OrgLimits represents rate limits for an organization
type OrgLimits struct {
	OrgID            string                 `json:"org_id"`
	Plan             string                 `json:"plan"`
	RequestsPerHour  int64                  `json:"requests_per_hour"`
	RequestsPerDay   int64                  `json:"requests_per_day"`
	RequestsPerMonth int64                  `json:"requests_per_month"`
	BandwidthPerDay  int64                  `json:"bandwidth_per_day"`
	BandwidthPerMonth int64                 `json:"bandwidth_per_month"`
	MaxUsers         int64                  `json:"max_users"`
	MaxConcurrentConns int64               `json:"max_concurrent_connections"`
	CustomLimits     map[string]int64       `json:"custom_limits,omitempty"`
	Features         []string               `json:"features,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	Enabled          bool                   `json:"enabled"`
}

// LimitType defines different types of limits
type LimitType string

const (
	LimitTypeRequestsPerHour   LimitType = "requests_per_hour"
	LimitTypeRequestsPerDay    LimitType = "requests_per_day"
	LimitTypeRequestsPerMonth  LimitType = "requests_per_month"
	LimitTypeBandwidthPerDay   LimitType = "bandwidth_per_day"
	LimitTypeBandwidthPerMonth LimitType = "bandwidth_per_month"
	LimitTypeConcurrentConns   LimitType = "concurrent_connections"
	LimitTypeCustom            LimitType = "custom"
)

// LimitPeriod defines time periods for limits
type LimitPeriod string

const (
	PeriodHour  LimitPeriod = "hour"
	PeriodDay   LimitPeriod = "day"
	PeriodMonth LimitPeriod = "month"
)

// UserOrgLimitManager manages per-user and per-organization rate limits
type UserOrgLimitManager struct {
	storage       UserOrgLimitStorage
	bucketManager *TokenBucketManager
	logger        *logrus.Logger
	defaultTiers  map[string]*UserLimits
	defaultPlans  map[string]*OrgLimits
}

// UserOrgLimitStorage defines interface for user/org limit persistence
type UserOrgLimitStorage interface {
	// User limits
	SaveUserLimits(ctx context.Context, limits *UserLimits) error
	LoadUserLimits(ctx context.Context, userID string) (*UserLimits, error)
	DeleteUserLimits(ctx context.Context, userID string) error
	ListUserLimits(ctx context.Context, orgID string) ([]*UserLimits, error)
	
	// Organization limits
	SaveOrgLimits(ctx context.Context, limits *OrgLimits) error
	LoadOrgLimits(ctx context.Context, orgID string) (*OrgLimits, error)
	DeleteOrgLimits(ctx context.Context, orgID string) error
	ListOrgLimits(ctx context.Context) ([]*OrgLimits, error)
	
	// Usage tracking
	IncrementUsage(ctx context.Context, userID, orgID string, limitType LimitType, amount int64) error
	GetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) (int64, error)
	ResetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) error
	
	// Statistics
	GetLimitStats(ctx context.Context) (*LimitStats, error)
}

// LimitStats contains statistics about user/org limits
type LimitStats struct {
	TotalUsers         int64            `json:"total_users"`
	TotalOrgs          int64            `json:"total_orgs"`
	UsersByTier        map[string]int64 `json:"users_by_tier"`
	OrgsByPlan         map[string]int64 `json:"orgs_by_plan"`
	LimitViolations    int64            `json:"limit_violations"`
	TopUsageUsers      []UserUsage      `json:"top_usage_users"`
	TopUsageOrgs       []OrgUsage       `json:"top_usage_orgs"`
	LastUpdated        time.Time        `json:"last_updated"`
}

// UserUsage represents usage statistics for a user
type UserUsage struct {
	UserID           string `json:"user_id"`
	OrgID            string `json:"org_id"`
	RequestsToday    int64  `json:"requests_today"`
	BandwidthToday   int64  `json:"bandwidth_today"`
	RequestsThisMonth int64  `json:"requests_this_month"`
	BandwidthThisMonth int64 `json:"bandwidth_this_month"`
}

// OrgUsage represents usage statistics for an organization
type OrgUsage struct {
	OrgID             string `json:"org_id"`
	RequestsToday     int64  `json:"requests_today"`
	BandwidthToday    int64  `json:"bandwidth_today"`
	RequestsThisMonth int64  `json:"requests_this_month"`
	BandwidthThisMonth int64 `json:"bandwidth_this_month"`
	ActiveUsers       int64  `json:"active_users"`
}

// LimitCheckRequest represents a request to check limits
type LimitCheckRequest struct {
	UserID      string    `json:"user_id"`
	OrgID       string    `json:"org_id"`
	LimitType   LimitType `json:"limit_type"`
	Amount      int64     `json:"amount"`
	RequestSize int64     `json:"request_size,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// LimitCheckResult represents the result of a limit check
type LimitCheckResult struct {
	Allowed         bool      `json:"allowed"`
	LimitType       LimitType `json:"limit_type"`
	CurrentUsage    int64     `json:"current_usage"`
	Limit           int64     `json:"limit"`
	RemainingQuota  int64     `json:"remaining_quota"`
	ResetTime       time.Time `json:"reset_time"`
	ViolationType   string    `json:"violation_type,omitempty"`
	UserLimits      *UserLimits `json:"user_limits,omitempty"`
	OrgLimits       *OrgLimits  `json:"org_limits,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// NewUserOrgLimitManager creates a new user/org limit manager
func NewUserOrgLimitManager(storage UserOrgLimitStorage, bucketManager *TokenBucketManager, logger *logrus.Logger) *UserOrgLimitManager {
	manager := &UserOrgLimitManager{
		storage:       storage,
		bucketManager: bucketManager,
		logger:        logger,
		defaultTiers:  make(map[string]*UserLimits),
		defaultPlans:  make(map[string]*OrgLimits),
	}
	
	// Initialize default tiers and plans
	manager.initializeDefaults()
	
	return manager
}

// initializeDefaults sets up default user tiers and organization plans
func (m *UserOrgLimitManager) initializeDefaults() {
	// Default user tiers
	m.defaultTiers["free"] = &UserLimits{
		Tier:             "free",
		RequestsPerHour:  100,
		RequestsPerDay:   1000,
		RequestsPerMonth: 10000,
		BandwidthPerDay:  100 * 1024 * 1024,  // 100MB
		BandwidthPerMonth: 1024 * 1024 * 1024, // 1GB
		ConcurrentConns:  5,
		Enabled:          true,
	}
	
	m.defaultTiers["basic"] = &UserLimits{
		Tier:             "basic",
		RequestsPerHour:  1000,
		RequestsPerDay:   10000,
		RequestsPerMonth: 100000,
		BandwidthPerDay:  1024 * 1024 * 1024,    // 1GB
		BandwidthPerMonth: 10 * 1024 * 1024 * 1024, // 10GB
		ConcurrentConns:  20,
		Enabled:          true,
	}
	
	m.defaultTiers["premium"] = &UserLimits{
		Tier:             "premium",
		RequestsPerHour:  10000,
		RequestsPerDay:   100000,
		RequestsPerMonth: 1000000,
		BandwidthPerDay:  10 * 1024 * 1024 * 1024,   // 10GB
		BandwidthPerMonth: 100 * 1024 * 1024 * 1024,  // 100GB
		ConcurrentConns:  100,
		Enabled:          true,
	}
	
	// Default organization plans
	m.defaultPlans["startup"] = &OrgLimits{
		Plan:             "startup",
		RequestsPerHour:  5000,
		RequestsPerDay:   50000,
		RequestsPerMonth: 500000,
		BandwidthPerDay:  5 * 1024 * 1024 * 1024,    // 5GB
		BandwidthPerMonth: 50 * 1024 * 1024 * 1024,   // 50GB
		MaxUsers:         10,
		MaxConcurrentConns: 100,
		Features:         []string{"basic_analytics", "email_support"},
		Enabled:          true,
	}
	
	m.defaultPlans["business"] = &OrgLimits{
		Plan:             "business",
		RequestsPerHour:  50000,
		RequestsPerDay:   500000,
		RequestsPerMonth: 5000000,
		BandwidthPerDay:  50 * 1024 * 1024 * 1024,   // 50GB
		BandwidthPerMonth: 500 * 1024 * 1024 * 1024,  // 500GB
		MaxUsers:         100,
		MaxConcurrentConns: 1000,
		Features:         []string{"advanced_analytics", "priority_support", "custom_rules"},
		Enabled:          true,
	}
	
	m.defaultPlans["enterprise"] = &OrgLimits{
		Plan:             "enterprise",
		RequestsPerHour:  500000,
		RequestsPerDay:   5000000,
		RequestsPerMonth: 50000000,
		BandwidthPerDay:  500 * 1024 * 1024 * 1024,  // 500GB
		BandwidthPerMonth: 5000 * 1024 * 1024 * 1024, // 5TB
		MaxUsers:         1000,
		MaxConcurrentConns: 10000,
		Features:         []string{"full_analytics", "24x7_support", "custom_rules", "white_label", "sla"},
		Enabled:          true,
	}
}

// SetUserLimits sets rate limits for a specific user
func (m *UserOrgLimitManager) SetUserLimits(ctx context.Context, limits *UserLimits) error {
	if limits.UserID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	limits.UpdatedAt = time.Now()
	if limits.CreatedAt.IsZero() {
		limits.CreatedAt = time.Now()
	}
	
	if err := m.storage.SaveUserLimits(ctx, limits); err != nil {
		return fmt.Errorf("failed to save user limits: %w", err)
	}
	
	m.logger.Infof("Set user limits for %s (tier: %s)", limits.UserID, limits.Tier)
	return nil
}

// GetUserLimits gets rate limits for a specific user
func (m *UserOrgLimitManager) GetUserLimits(ctx context.Context, userID string) (*UserLimits, error) {
	limits, err := m.storage.LoadUserLimits(ctx, userID)
	if err != nil {
		// If user limits not found, try to get from default tier
		return nil, fmt.Errorf("user limits not found: %s", userID)
	}
	
	return limits, nil
}

// GetUserLimitsWithDefaults gets user limits with fallback to defaults
func (m *UserOrgLimitManager) GetUserLimitsWithDefaults(ctx context.Context, userID, tier string) (*UserLimits, error) {
	// Try to get user-specific limits first
	limits, err := m.storage.LoadUserLimits(ctx, userID)
	if err == nil {
		return limits, nil
	}
	
	// Fallback to default tier limits
	if defaultLimits, exists := m.defaultTiers[tier]; exists {
		// Create a copy with user ID
		userLimits := *defaultLimits
		userLimits.UserID = userID
		return &userLimits, nil
	}
	
	// Fallback to free tier if tier not found
	if defaultLimits, exists := m.defaultTiers["free"]; exists {
		userLimits := *defaultLimits
		userLimits.UserID = userID
		return &userLimits, nil
	}
	
	return nil, fmt.Errorf("no limits found for user %s", userID)
}

// SetOrgLimits sets rate limits for an organization
func (m *UserOrgLimitManager) SetOrgLimits(ctx context.Context, limits *OrgLimits) error {
	if limits.OrgID == "" {
		return fmt.Errorf("organization ID cannot be empty")
	}
	
	limits.UpdatedAt = time.Now()
	if limits.CreatedAt.IsZero() {
		limits.CreatedAt = time.Now()
	}
	
	if err := m.storage.SaveOrgLimits(ctx, limits); err != nil {
		return fmt.Errorf("failed to save org limits: %w", err)
	}
	
	m.logger.Infof("Set org limits for %s (plan: %s)", limits.OrgID, limits.Plan)
	return nil
}

// GetOrgLimits gets rate limits for an organization
func (m *UserOrgLimitManager) GetOrgLimits(ctx context.Context, orgID string) (*OrgLimits, error) {
	limits, err := m.storage.LoadOrgLimits(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org limits not found: %s", orgID)
	}
	
	return limits, nil
}

// GetOrgLimitsWithDefaults gets org limits with fallback to defaults
func (m *UserOrgLimitManager) GetOrgLimitsWithDefaults(ctx context.Context, orgID, plan string) (*OrgLimits, error) {
	// Try to get org-specific limits first
	limits, err := m.storage.LoadOrgLimits(ctx, orgID)
	if err == nil {
		return limits, nil
	}
	
	// Fallback to default plan limits
	if defaultLimits, exists := m.defaultPlans[plan]; exists {
		// Create a copy with org ID
		orgLimits := *defaultLimits
		orgLimits.OrgID = orgID
		return &orgLimits, nil
	}
	
	// Fallback to startup plan if plan not found
	if defaultLimits, exists := m.defaultPlans["startup"]; exists {
		orgLimits := *defaultLimits
		orgLimits.OrgID = orgID
		return &orgLimits, nil
	}
	
	return nil, fmt.Errorf("no limits found for org %s", orgID)
}

// CheckLimits checks if a request is within user and org limits
func (m *UserOrgLimitManager) CheckLimits(ctx context.Context, request *LimitCheckRequest) (*LimitCheckResult, error) {
	// Get user limits
	userLimits, err := m.GetUserLimitsWithDefaults(ctx, request.UserID, "free")
	if err != nil {
		return nil, fmt.Errorf("failed to get user limits: %w", err)
	}
	
	// Get org limits
	orgLimits, err := m.GetOrgLimitsWithDefaults(ctx, request.OrgID, "startup")
	if err != nil {
		return nil, fmt.Errorf("failed to get org limits: %w", err)
	}
	
	// Check user limits first
	userResult, err := m.checkUserLimit(ctx, request, userLimits)
	if err != nil {
		return nil, fmt.Errorf("failed to check user limits: %w", err)
	}
	
	if !userResult.Allowed {
		return userResult, nil
	}
	
	// Check org limits
	orgResult, err := m.checkOrgLimit(ctx, request, orgLimits)
	if err != nil {
		return nil, fmt.Errorf("failed to check org limits: %w", err)
	}
	
	// Return the most restrictive result
	if !orgResult.Allowed {
		return orgResult, nil
	}
	
	// If both allow, return user result (more specific)
	return userResult, nil
}

// checkUserLimit checks user-specific limits
func (m *UserOrgLimitManager) checkUserLimit(ctx context.Context, request *LimitCheckRequest, limits *UserLimits) (*LimitCheckResult, error) {
	var currentUsage, limit int64
	var resetTime time.Time
	var period LimitPeriod
	
	switch request.LimitType {
	case LimitTypeRequestsPerHour:
		limit = limits.RequestsPerHour
		period = PeriodHour
		resetTime = time.Now().Truncate(time.Hour).Add(time.Hour)
	case LimitTypeRequestsPerDay:
		limit = limits.RequestsPerDay
		period = PeriodDay
		resetTime = time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	case LimitTypeRequestsPerMonth:
		limit = limits.RequestsPerMonth
		period = PeriodMonth
		resetTime = time.Now().AddDate(0, 1, 0)
	case LimitTypeBandwidthPerDay:
		limit = limits.BandwidthPerDay
		period = PeriodDay
		resetTime = time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	case LimitTypeBandwidthPerMonth:
		limit = limits.BandwidthPerMonth
		period = PeriodMonth
		resetTime = time.Now().AddDate(0, 1, 0)
	default:
		return nil, fmt.Errorf("unsupported limit type: %s", request.LimitType)
	}
	
	// Get current usage
	usage, err := m.storage.GetUsage(ctx, request.UserID, request.OrgID, request.LimitType, period)
	if err != nil {
		m.logger.Warnf("Failed to get usage for user %s: %v", request.UserID, err)
		usage = 0
	}
	currentUsage = usage
	
	// Check if request would exceed limit
	newUsage := currentUsage + request.Amount
	allowed := newUsage <= limit
	
	result := &LimitCheckResult{
		Allowed:        allowed,
		LimitType:      request.LimitType,
		CurrentUsage:   currentUsage,
		Limit:          limit,
		RemainingQuota: limit - currentUsage,
		ResetTime:      resetTime,
		UserLimits:     limits,
		Timestamp:      time.Now(),
	}
	
	if !allowed {
		result.ViolationType = "user_limit"
	}
	
	return result, nil
}

// checkOrgLimit checks organization-specific limits
func (m *UserOrgLimitManager) checkOrgLimit(ctx context.Context, request *LimitCheckRequest, limits *OrgLimits) (*LimitCheckResult, error) {
	var currentUsage, limit int64
	var resetTime time.Time
	var period LimitPeriod
	
	switch request.LimitType {
	case LimitTypeRequestsPerHour:
		limit = limits.RequestsPerHour
		period = PeriodHour
		resetTime = time.Now().Truncate(time.Hour).Add(time.Hour)
	case LimitTypeRequestsPerDay:
		limit = limits.RequestsPerDay
		period = PeriodDay
		resetTime = time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	case LimitTypeRequestsPerMonth:
		limit = limits.RequestsPerMonth
		period = PeriodMonth
		resetTime = time.Now().AddDate(0, 1, 0)
	case LimitTypeBandwidthPerDay:
		limit = limits.BandwidthPerDay
		period = PeriodDay
		resetTime = time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	case LimitTypeBandwidthPerMonth:
		limit = limits.BandwidthPerMonth
		period = PeriodMonth
		resetTime = time.Now().AddDate(0, 1, 0)
	default:
		return nil, fmt.Errorf("unsupported limit type: %s", request.LimitType)
	}
	
	// Get current usage for the entire org
	usage, err := m.storage.GetUsage(ctx, "", request.OrgID, request.LimitType, period)
	if err != nil {
		m.logger.Warnf("Failed to get usage for org %s: %v", request.OrgID, err)
		usage = 0
	}
	currentUsage = usage
	
	// Check if request would exceed limit
	newUsage := currentUsage + request.Amount
	allowed := newUsage <= limit
	
	result := &LimitCheckResult{
		Allowed:        allowed,
		LimitType:      request.LimitType,
		CurrentUsage:   currentUsage,
		Limit:          limit,
		RemainingQuota: limit - currentUsage,
		ResetTime:      resetTime,
		OrgLimits:      limits,
		Timestamp:      time.Now(),
	}
	
	if !allowed {
		result.ViolationType = "org_limit"
	}
	
	return result, nil
}

// IncrementUsage increments usage counters for user and org
func (m *UserOrgLimitManager) IncrementUsage(ctx context.Context, userID, orgID string, limitType LimitType, amount int64) error {
	// Increment user usage
	if err := m.storage.IncrementUsage(ctx, userID, orgID, limitType, amount); err != nil {
		m.logger.Errorf("Failed to increment user usage: %v", err)
	}
	
	// Increment org usage
	if err := m.storage.IncrementUsage(ctx, "", orgID, limitType, amount); err != nil {
		m.logger.Errorf("Failed to increment org usage: %v", err)
	}
	
	return nil
}

// GetStats returns statistics about user/org limits
func (m *UserOrgLimitManager) GetStats(ctx context.Context) (*LimitStats, error) {
	return m.storage.GetLimitStats(ctx)
}

// GetDefaultTiers returns default user tiers
func (m *UserOrgLimitManager) GetDefaultTiers() map[string]*UserLimits {
	return m.defaultTiers
}

// GetDefaultPlans returns default organization plans
func (m *UserOrgLimitManager) GetDefaultPlans() map[string]*OrgLimits {
	return m.defaultPlans
}