package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserOrgLimitStorage is a mock implementation of UserOrgLimitStorage
type MockUserOrgLimitStorage struct {
	mock.Mock
}

func (m *MockUserOrgLimitStorage) SaveUserLimits(ctx context.Context, limits *UserLimits) error {
	args := m.Called(ctx, limits)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) LoadUserLimits(ctx context.Context, userID string) (*UserLimits, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserLimits), args.Error(1)
}

func (m *MockUserOrgLimitStorage) DeleteUserLimits(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) ListUserLimits(ctx context.Context, orgID string) ([]*UserLimits, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*UserLimits), args.Error(1)
}

func (m *MockUserOrgLimitStorage) SaveOrgLimits(ctx context.Context, limits *OrgLimits) error {
	args := m.Called(ctx, limits)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) LoadOrgLimits(ctx context.Context, orgID string) (*OrgLimits, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OrgLimits), args.Error(1)
}

func (m *MockUserOrgLimitStorage) DeleteOrgLimits(ctx context.Context, orgID string) error {
	args := m.Called(ctx, orgID)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) ListOrgLimits(ctx context.Context) ([]*OrgLimits, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*OrgLimits), args.Error(1)
}

func (m *MockUserOrgLimitStorage) IncrementUsage(ctx context.Context, userID, orgID string, limitType LimitType, amount int64) error {
	args := m.Called(ctx, userID, orgID, limitType, amount)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) GetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) (int64, error) {
	args := m.Called(ctx, userID, orgID, limitType, period)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserOrgLimitStorage) ResetUsage(ctx context.Context, userID, orgID string, limitType LimitType, period LimitPeriod) error {
	args := m.Called(ctx, userID, orgID, limitType, period)
	return args.Error(0)
}

func (m *MockUserOrgLimitStorage) GetLimitStats(ctx context.Context) (*LimitStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*LimitStats), args.Error(1)
}

func TestUserOrgLimitManager_SetUserLimits(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	limits := &UserLimits{
		UserID:          "user123",
		OrgID:           "org456",
		Tier:            "premium",
		RequestsPerHour: 1000,
		RequestsPerDay:  10000,
		Enabled:         true,
	}
	
	mockStorage.On("SaveUserLimits", mock.Anything, mock.MatchedBy(func(l *UserLimits) bool {
		return l.UserID == "user123" && l.Tier == "premium"
	})).Return(nil)
	
	err := manager.SetUserLimits(context.Background(), limits)
	
	assert.NoError(t, err)
	assert.False(t, limits.CreatedAt.IsZero())
	assert.False(t, limits.UpdatedAt.IsZero())
	
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_GetUserLimitsWithDefaults(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	// Test case 1: User limits exist
	userLimits := &UserLimits{
		UserID:          "user123",
		Tier:            "premium",
		RequestsPerHour: 5000,
		Enabled:         true,
	}
	
	mockStorage.On("LoadUserLimits", mock.Anything, "user123").Return(userLimits, nil)
	
	result, err := manager.GetUserLimitsWithDefaults(context.Background(), "user123", "basic")
	
	assert.NoError(t, err)
	assert.Equal(t, "user123", result.UserID)
	assert.Equal(t, "premium", result.Tier)
	assert.Equal(t, int64(5000), result.RequestsPerHour)
	
	// Test case 2: User limits don't exist, use tier defaults
	mockStorage.On("LoadUserLimits", mock.Anything, "user456").Return(nil, assert.AnError)
	
	result2, err2 := manager.GetUserLimitsWithDefaults(context.Background(), "user456", "basic")
	
	assert.NoError(t, err2)
	assert.Equal(t, "user456", result2.UserID)
	assert.Equal(t, "basic", result2.Tier)
	assert.Equal(t, int64(1000), result2.RequestsPerHour) // From default basic tier
	
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_CheckLimits_UserLimit(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	userLimits := &UserLimits{
		UserID:          "user123",
		OrgID:           "org456",
		RequestsPerHour: 100,
		Enabled:         true,
	}
	
	orgLimits := &OrgLimits{
		OrgID:           "org456",
		RequestsPerHour: 1000,
		Enabled:         true,
	}
	
	// Mock storage calls
	mockStorage.On("LoadUserLimits", mock.Anything, "user123").Return(userLimits, nil)
	mockStorage.On("LoadOrgLimits", mock.Anything, "org456").Return(orgLimits, nil)
	mockStorage.On("GetUsage", mock.Anything, "user123", "org456", LimitTypeRequestsPerHour, PeriodHour).Return(int64(50), nil)
	mockStorage.On("GetUsage", mock.Anything, "", "org456", LimitTypeRequestsPerHour, PeriodHour).Return(int64(200), nil)
	
	request := &LimitCheckRequest{
		UserID:    "user123",
		OrgID:     "org456",
		LimitType: LimitTypeRequestsPerHour,
		Amount:    10,
		Timestamp: time.Now(),
	}
	
	result, err := manager.CheckLimits(context.Background(), request)
	
	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, int64(50), result.CurrentUsage)
	assert.Equal(t, int64(100), result.Limit)
	assert.Equal(t, int64(50), result.RemainingQuota) // 100 - 50
	
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_CheckLimits_UserLimitExceeded(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	userLimits := &UserLimits{
		UserID:          "user123",
		OrgID:           "org456",
		RequestsPerHour: 100,
		Enabled:         true,
	}
	
	orgLimits := &OrgLimits{
		OrgID:           "org456",
		RequestsPerHour: 1000,
		Enabled:         true,
	}
	
	// Mock storage calls - user is at 95/100, requesting 10 more (would exceed)
	mockStorage.On("LoadUserLimits", mock.Anything, "user123").Return(userLimits, nil)
	mockStorage.On("LoadOrgLimits", mock.Anything, "org456").Return(orgLimits, nil)
	mockStorage.On("GetUsage", mock.Anything, "user123", "org456", LimitTypeRequestsPerHour, PeriodHour).Return(int64(95), nil)
	
	request := &LimitCheckRequest{
		UserID:    "user123",
		OrgID:     "org456",
		LimitType: LimitTypeRequestsPerHour,
		Amount:    10,
		Timestamp: time.Now(),
	}
	
	result, err := manager.CheckLimits(context.Background(), request)
	
	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "user_limit", result.ViolationType)
	assert.Equal(t, int64(95), result.CurrentUsage)
	assert.Equal(t, int64(100), result.Limit)
	assert.Equal(t, int64(5), result.RemainingQuota) // 100 - 95
	
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_CheckLimits_OrgLimitExceeded(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	userLimits := &UserLimits{
		UserID:          "user123",
		OrgID:           "org456",
		RequestsPerHour: 100,
		Enabled:         true,
	}
	
	orgLimits := &OrgLimits{
		OrgID:           "org456",
		RequestsPerHour: 1000,
		Enabled:         true,
	}
	
	// Mock storage calls - user is fine (50/100), but org is at limit (995/1000)
	mockStorage.On("LoadUserLimits", mock.Anything, "user123").Return(userLimits, nil)
	mockStorage.On("LoadOrgLimits", mock.Anything, "org456").Return(orgLimits, nil)
	mockStorage.On("GetUsage", mock.Anything, "user123", "org456", LimitTypeRequestsPerHour, PeriodHour).Return(int64(50), nil)
	mockStorage.On("GetUsage", mock.Anything, "", "org456", LimitTypeRequestsPerHour, PeriodHour).Return(int64(995), nil)
	
	request := &LimitCheckRequest{
		UserID:    "user123",
		OrgID:     "org456",
		LimitType: LimitTypeRequestsPerHour,
		Amount:    10,
		Timestamp: time.Now(),
	}
	
	result, err := manager.CheckLimits(context.Background(), request)
	
	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "org_limit", result.ViolationType)
	assert.Equal(t, int64(995), result.CurrentUsage)
	assert.Equal(t, int64(1000), result.Limit)
	assert.Equal(t, int64(5), result.RemainingQuota) // 1000 - 995
	
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_IncrementUsage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	// Mock storage calls for both user and org usage increment
	mockStorage.On("IncrementUsage", mock.Anything, "user123", "org456", LimitTypeRequestsPerHour, int64(5)).Return(nil)
	mockStorage.On("IncrementUsage", mock.Anything, "", "org456", LimitTypeRequestsPerHour, int64(5)).Return(nil)
	
	err := manager.IncrementUsage(context.Background(), "user123", "org456", LimitTypeRequestsPerHour, 5)
	
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func TestUserOrgLimitManager_GetDefaultTiers(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	tiers := manager.GetDefaultTiers()
	
	assert.Contains(t, tiers, "free")
	assert.Contains(t, tiers, "basic")
	assert.Contains(t, tiers, "premium")
	
	// Check free tier limits
	freeTier := tiers["free"]
	assert.Equal(t, int64(100), freeTier.RequestsPerHour)
	assert.Equal(t, int64(1000), freeTier.RequestsPerDay)
	assert.Equal(t, int64(5), freeTier.ConcurrentConns)
	
	// Check premium tier limits
	premiumTier := tiers["premium"]
	assert.Equal(t, int64(10000), premiumTier.RequestsPerHour)
	assert.Equal(t, int64(100000), premiumTier.RequestsPerDay)
	assert.Equal(t, int64(100), premiumTier.ConcurrentConns)
}

func TestUserOrgLimitManager_GetDefaultPlans(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logger)
	
	plans := manager.GetDefaultPlans()
	
	assert.Contains(t, plans, "startup")
	assert.Contains(t, plans, "business")
	assert.Contains(t, plans, "enterprise")
	
	// Check startup plan limits
	startupPlan := plans["startup"]
	assert.Equal(t, int64(5000), startupPlan.RequestsPerHour)
	assert.Equal(t, int64(10), startupPlan.MaxUsers)
	assert.Contains(t, startupPlan.Features, "basic_analytics")
	
	// Check enterprise plan limits
	enterprisePlan := plans["enterprise"]
	assert.Equal(t, int64(500000), enterprisePlan.RequestsPerHour)
	assert.Equal(t, int64(1000), enterprisePlan.MaxUsers)
	assert.Contains(t, enterprisePlan.Features, "white_label")
	assert.Contains(t, enterprisePlan.Features, "sla")
}

func TestUserOrgAwareStrategy(t *testing.T) {
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logrus.New())
	
	strategy := NewUserOrgAwareStrategy(manager, LimitTypeRequestsPerHour)
	
	request := &RateLimitRequest{
		UserID:      "user123",
		OrgID:       "org456",
		RequestSize: 1024,
	}
	
	assert.Equal(t, "user_org:user123:org456:requests_per_hour", strategy.GetBucketKey(request))
	assert.Equal(t, "dynamic_requests_per_hour", strategy.GetConfigName(request))
	assert.Equal(t, int64(1), strategy.GetTokensRequired(request))
	assert.Equal(t, "user_org_requests_per_hour", strategy.GetStrategyName())
}

func TestUserOrgAwareStrategy_BandwidthTokens(t *testing.T) {
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logrus.New())
	
	strategy := NewUserOrgAwareStrategy(manager, LimitTypeBandwidthPerDay)
	
	request := &RateLimitRequest{
		UserID:      "user123",
		OrgID:       "org456",
		RequestSize: 2048, // 2KB
	}
	
	assert.Equal(t, int64(2048), strategy.GetTokensRequired(request))
	assert.Equal(t, "user_org_bandwidth_per_day", strategy.GetStrategyName())
}

func TestHierarchicalStrategy(t *testing.T) {
	mockStorage := &MockUserOrgLimitStorage{}
	manager := NewUserOrgLimitManager(mockStorage, nil, logrus.New())
	
	strategy := NewHierarchicalStrategy(manager, LimitTypeRequestsPerDay)
	
	request := &RateLimitRequest{
		UserID: "user123",
		OrgID:  "org456",
	}
	
	assert.Equal(t, "hierarchical:org456:user123:requests_per_day", strategy.GetBucketKey(request))
	assert.Equal(t, "hierarchical_requests_per_day", strategy.GetConfigName(request))
	assert.Equal(t, int64(1), strategy.GetTokensRequired(request))
	assert.Equal(t, "hierarchical_requests_per_day", strategy.GetStrategyName())
}