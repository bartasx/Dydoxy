package filter

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockListStorage is a mock implementation of ListStorage
type MockListStorage struct {
	mock.Mock
}

func (m *MockListStorage) SaveEntry(ctx context.Context, entry *ListEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockListStorage) LoadEntry(ctx context.Context, entryID string) (*ListEntry, error) {
	args := m.Called(ctx, entryID)
	return args.Get(0).(*ListEntry), args.Error(1)
}

func (m *MockListStorage) DeleteEntry(ctx context.Context, entryID string) error {
	args := m.Called(ctx, entryID)
	return args.Error(0)
}

func (m *MockListStorage) SearchEntries(ctx context.Context, query *ListSearchQuery) ([]*ListEntry, int64, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]*ListEntry), args.Get(1).(int64), args.Error(2)
}

func (m *MockListStorage) CheckValue(ctx context.Context, value string) (*ListEntry, error) {
	args := m.Called(ctx, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListEntry), args.Error(1)
}

func (m *MockListStorage) GetStats(ctx context.Context) (*ListStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*ListStats), args.Error(1)
}

func (m *MockListStorage) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockListStorage) BulkSave(ctx context.Context, entries []*ListEntry) error {
	args := m.Called(ctx, entries)
	return args.Error(0)
}

func (m *MockListStorage) BulkDelete(ctx context.Context, entryIDs []string) error {
	args := m.Called(ctx, entryIDs)
	return args.Error(0)
}

func TestManager_AddEntry(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	entry := &ListEntry{
		Value:    "malware.com",
		Type:     ListTypeBlacklist,
		Category: string(CategoryMalware),
		Source:   string(SourceManual),
		Enabled:  true,
	}
	
	mockStorage.On("SaveEntry", mock.Anything, mock.MatchedBy(func(e *ListEntry) bool {
		return e.Value == "malware.com" && e.Type == ListTypeBlacklist
	})).Return(nil)
	
	err := manager.AddEntry(context.Background(), entry)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, entry.ID)
	assert.False(t, entry.CreatedAt.IsZero())
	assert.False(t, entry.UpdatedAt.IsZero())
	
	mockStorage.AssertExpectations(t)
}

func TestManager_CheckValue_Blacklist(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	blacklistEntry := &ListEntry{
		ID:       "test-id",
		Value:    "malware.com",
		Type:     ListTypeBlacklist,
		Category: string(CategoryMalware),
		Enabled:  true,
	}
	
	mockStorage.On("CheckValue", mock.Anything, "malware.com").Return(blacklistEntry, nil)
	
	result, err := manager.CheckValue(context.Background(), "malware.com")
	
	assert.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, ListTypeBlacklist, result.ListType)
	assert.Equal(t, "block", result.Action)
	assert.Contains(t, result.Reason, "blacklist")
	
	mockStorage.AssertExpectations(t)
}

func TestManager_CheckValue_Whitelist(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	whitelistEntry := &ListEntry{
		ID:       "test-id",
		Value:    "trusted.com",
		Type:     ListTypeWhitelist,
		Category: string(CategoryBusiness),
		Enabled:  true,
	}
	
	mockStorage.On("CheckValue", mock.Anything, "trusted.com").Return(whitelistEntry, nil)
	
	result, err := manager.CheckValue(context.Background(), "trusted.com")
	
	assert.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, ListTypeWhitelist, result.ListType)
	assert.Equal(t, "allow", result.Action)
	assert.Contains(t, result.Reason, "whitelist")
	
	mockStorage.AssertExpectations(t)
}

func TestManager_CheckValue_NotFound(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	mockStorage.On("CheckValue", mock.Anything, "unknown.com").Return(nil, nil)
	
	result, err := manager.CheckValue(context.Background(), "unknown.com")
	
	assert.NoError(t, err)
	assert.False(t, result.Found)
	assert.Equal(t, "allow", result.Action)
	assert.Contains(t, result.Reason, "Not found")
	
	mockStorage.AssertExpectations(t)
}

func TestManager_ImportEntries(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	entries := []string{
		"malware1.com",
		"malware2.com",
		"", // Should be skipped
		"malware3.com",
	}
	
	mockStorage.On("BulkSave", mock.Anything, mock.MatchedBy(func(entries []*ListEntry) bool {
		return len(entries) == 3 // Empty entry should be skipped
	})).Return(nil)
	
	result, err := manager.ImportEntries(context.Background(), 
		ListTypeBlacklist, 
		SourceThreatFeed, 
		entries, 
		CategoryMalware)
	
	assert.NoError(t, err)
	assert.Equal(t, 4, result.TotalProcessed)
	assert.Equal(t, 3, result.Added)
	assert.Equal(t, 1, result.Skipped)
	assert.Equal(t, 0, result.Errors)
	
	mockStorage.AssertExpectations(t)
}

func TestManager_BulkOperation_Add(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	operation := &BulkOperation{
		Operation: "add",
		Entries:   []string{"domain1.com", "domain2.com"},
		Category:  string(CategoryMalware),
		Source:    string(SourceManual),
	}
	
	mockStorage.On("BulkSave", mock.Anything, mock.MatchedBy(func(entries []*ListEntry) bool {
		return len(entries) == 2
	})).Return(nil)
	
	result, err := manager.BulkOperation(context.Background(), operation)
	
	assert.NoError(t, err)
	assert.Equal(t, 2, result.TotalProcessed)
	assert.Equal(t, 2, result.Added)
	assert.Equal(t, 0, result.Errors)
	
	mockStorage.AssertExpectations(t)
}

func TestManager_BulkOperation_Remove(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	operation := &BulkOperation{
		Operation: "remove",
		Entries:   []string{"id1", "id2"},
	}
	
	mockStorage.On("BulkDelete", mock.Anything, []string{"id1", "id2"}).Return(nil)
	
	result, err := manager.BulkOperation(context.Background(), operation)
	
	assert.NoError(t, err)
	assert.Equal(t, 2, result.TotalProcessed)
	assert.Equal(t, 2, result.Added) // Actually removed
	assert.Equal(t, 0, result.Errors)
	
	mockStorage.AssertExpectations(t)
}

func TestManager_GetStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	expectedStats := &ListStats{
		BlacklistEntries: 100,
		WhitelistEntries: 50,
		CategoriesCount: map[string]int64{
			"malware":  60,
			"phishing": 40,
		},
		SourcesCount: map[string]int64{
			"manual":      30,
			"threat_feed": 120,
		},
		LastUpdated: time.Now(),
	}
	
	mockStorage.On("GetStats", mock.Anything).Return(expectedStats, nil)
	
	stats, err := manager.GetStats(context.Background())
	
	assert.NoError(t, err)
	assert.Equal(t, expectedStats.BlacklistEntries, stats.BlacklistEntries)
	assert.Equal(t, expectedStats.WhitelistEntries, stats.WhitelistEntries)
	assert.Equal(t, expectedStats.CategoriesCount, stats.CategoriesCount)
	assert.Equal(t, expectedStats.SourcesCount, stats.SourcesCount)
	
	mockStorage.AssertExpectations(t)
}

func TestManager_CleanupExpired(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	mockStorage.On("CleanupExpired", mock.Anything).Return(int64(5), nil)
	
	count, err := manager.CleanupExpired(context.Background())
	
	assert.NoError(t, err)
	assert.Equal(t, int64(5), count)
	
	mockStorage.AssertExpectations(t)
}

// MockThreatFeedProvider is a mock implementation of ThreatFeedProvider
type MockThreatFeedProvider struct {
	mock.Mock
	name    string
	enabled bool
}

func (m *MockThreatFeedProvider) GetName() string {
	return m.name
}

func (m *MockThreatFeedProvider) FetchEntries(ctx context.Context) ([]*ListEntry, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*ListEntry), args.Error(1)
}

func (m *MockThreatFeedProvider) GetLastUpdate() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *MockThreatFeedProvider) IsEnabled() bool {
	return m.enabled
}

func TestManager_SyncWithThreatFeeds(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockListStorage{}
	manager := NewManager(mockStorage, logger)
	
	// Create mock threat feed provider
	mockProvider := &MockThreatFeedProvider{
		name:    "TestFeed",
		enabled: true,
	}
	
	entries := []*ListEntry{
		{
			ID:       "feed-1",
			Value:    "threat1.com",
			Type:     ListTypeBlacklist,
			Category: string(CategoryMalware),
			Source:   string(SourceThreatFeed),
		},
		{
			ID:       "feed-2",
			Value:    "threat2.com",
			Type:     ListTypeBlacklist,
			Category: string(CategoryPhishing),
			Source:   string(SourceThreatFeed),
		},
	}
	
	mockProvider.On("FetchEntries", mock.Anything).Return(entries, nil)
	mockStorage.On("BulkSave", mock.Anything, entries).Return(nil)
	
	manager.RegisterThreatFeedProvider(mockProvider)
	
	err := manager.SyncWithThreatFeeds(context.Background())
	
	assert.NoError(t, err)
	
	mockProvider.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}