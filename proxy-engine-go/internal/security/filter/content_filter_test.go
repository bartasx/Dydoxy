package filter

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a mock implementation of RuleStorage
type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) SaveRule(ctx context.Context, rule *FilterRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockStorage) LoadRules(ctx context.Context) ([]*FilterRule, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*FilterRule), args.Error(1)
}

func (m *MockStorage) DeleteRule(ctx context.Context, ruleID string) error {
	args := m.Called(ctx, ruleID)
	return args.Error(0)
}

func (m *MockStorage) UpdateRule(ctx context.Context, rule *FilterRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func TestEngine_Filter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
	
	mockStorage := &MockStorage{}
	engine := NewEngine(mockStorage, logger)
	
	// Add test rules
	blockRule := &FilterRule{
		ID:       "block-rule",
		Name:     "Block Social Media",
		Pattern:  "facebook.com",
		Type:     RuleTypeDomain,
		Action:   ActionBlock,
		Priority: 100,
		Enabled:  true,
	}
	
	allowRule := &FilterRule{
		ID:       "allow-rule",
		Name:     "Allow Google",
		Pattern:  "google.com",
		Type:     RuleTypeDomain,
		Action:   ActionAllow,
		Priority: 50,
		Enabled:  true,
	}
	
	engine.rules = []*FilterRule{blockRule, allowRule}
	
	tests := []struct {
		name     string
		request  *ContentRequest
		expected bool
		action   FilterAction
	}{
		{
			name: "Block Facebook",
			request: &ContentRequest{
				URL:    "https://www.facebook.com/login",
				Domain: "www.facebook.com",
				UserID: "user1",
			},
			expected: false,
			action:   ActionBlock,
		},
		{
			name: "Allow Google",
			request: &ContentRequest{
				URL:    "https://www.google.com/search",
				Domain: "www.google.com",
				UserID: "user1",
			},
			expected: true,
			action:   ActionAllow,
		},
		{
			name: "Allow Unknown Domain",
			request: &ContentRequest{
				URL:    "https://example.com",
				Domain: "example.com",
				UserID: "user1",
			},
			expected: true,
			action:   ActionAllow,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Filter(context.Background(), tt.request)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result.Allowed)
			assert.Equal(t, tt.action, result.Action)
		})
	}
}

func TestEngine_AddRule(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockStorage{}
	engine := NewEngine(mockStorage, logger)
	
	rule := &FilterRule{
		ID:      "test-rule",
		Name:    "Test Rule",
		Pattern: "test.com",
		Type:    RuleTypeDomain,
		Action:  ActionBlock,
		Enabled: true,
	}
	
	mockStorage.On("SaveRule", mock.Anything, rule).Return(nil)
	
	err := engine.AddRule(context.Background(), rule)
	
	assert.NoError(t, err)
	assert.Len(t, engine.rules, 1)
	assert.Equal(t, rule.ID, engine.rules[0].ID)
	
	mockStorage.AssertExpectations(t)
}

func TestEngine_RemoveRule(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	mockStorage := &MockStorage{}
	engine := NewEngine(mockStorage, logger)
	
	rule := &FilterRule{
		ID:      "test-rule",
		Name:    "Test Rule",
		Pattern: "test.com",
		Type:    RuleTypeDomain,
		Action:  ActionBlock,
		Enabled: true,
	}
	
	engine.rules = []*FilterRule{rule}
	
	mockStorage.On("DeleteRule", mock.Anything, "test-rule").Return(nil)
	
	err := engine.RemoveRule(context.Background(), "test-rule")
	
	assert.NoError(t, err)
	assert.Len(t, engine.rules, 0)
	
	mockStorage.AssertExpectations(t)
}

func TestDomainMatcher(t *testing.T) {
	matcher := NewDomainMatcher()
	
	tests := []struct {
		name     string
		domain   string
		pattern  string
		expected bool
	}{
		{
			name:     "Exact match",
			domain:   "example.com",
			pattern:  "example.com",
			expected: true,
		},
		{
			name:     "Subdomain match",
			domain:   "www.example.com",
			pattern:  "example.com",
			expected: true,
		},
		{
			name:     "No match",
			domain:   "google.com",
			pattern:  "example.com",
			expected: false,
		},
		{
			name:     "Partial match should not work",
			domain:   "notexample.com",
			pattern:  "example.com",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &ContentRequest{Domain: tt.domain}
			rule := &FilterRule{Pattern: tt.pattern}
			
			result := matcher.Match(request, rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestURLMatcher(t *testing.T) {
	matcher := NewURLMatcher()
	
	tests := []struct {
		name     string
		url      string
		pattern  string
		expected bool
	}{
		{
			name:     "URL contains pattern",
			url:      "https://example.com/admin/login",
			pattern:  "admin",
			expected: true,
		},
		{
			name:     "URL does not contain pattern",
			url:      "https://example.com/public/page",
			pattern:  "admin",
			expected: false,
		},
		{
			name:     "Case insensitive match",
			url:      "https://example.com/ADMIN/login",
			pattern:  "admin",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &ContentRequest{URL: tt.url}
			rule := &FilterRule{Pattern: tt.pattern}
			
			result := matcher.Match(request, rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKeywordMatcher(t *testing.T) {
	matcher := NewKeywordMatcher()
	
	tests := []struct {
		name     string
		request  *ContentRequest
		pattern  string
		expected bool
	}{
		{
			name: "Keyword in URL",
			request: &ContentRequest{
				URL: "https://example.com/gambling/casino",
			},
			pattern:  "gambling",
			expected: true,
		},
		{
			name: "Keyword in header",
			request: &ContentRequest{
				URL: "https://example.com/page",
				Headers: map[string]string{
					"User-Agent": "gambling-bot",
				},
			},
			pattern:  "gambling",
			expected: true,
		},
		{
			name: "Keyword in body",
			request: &ContentRequest{
				URL:  "https://example.com/page",
				Body: []byte("This page contains gambling content"),
			},
			pattern:  "gambling",
			expected: true,
		},
		{
			name: "No keyword match",
			request: &ContentRequest{
				URL: "https://example.com/safe-content",
			},
			pattern:  "gambling",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &FilterRule{Pattern: tt.pattern}
			
			result := matcher.Match(tt.request, rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFileExtensionMatcher(t *testing.T) {
	matcher := NewFileExtensionMatcher()
	
	tests := []struct {
		name     string
		url      string
		pattern  string
		expected bool
	}{
		{
			name:     "Match .exe extension",
			url:      "https://example.com/download/file.exe",
			pattern:  ".exe",
			expected: true,
		},
		{
			name:     "Match extension without dot in pattern",
			url:      "https://example.com/download/file.exe",
			pattern:  "exe",
			expected: true,
		},
		{
			name:     "No extension match",
			url:      "https://example.com/download/file.txt",
			pattern:  ".exe",
			expected: false,
		},
		{
			name:     "Case insensitive match",
			url:      "https://example.com/download/FILE.EXE",
			pattern:  ".exe",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &ContentRequest{URL: tt.url}
			rule := &FilterRule{Pattern: tt.pattern}
			
			result := matcher.Match(request, rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}