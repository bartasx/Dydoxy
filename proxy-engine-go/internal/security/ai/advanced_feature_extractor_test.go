package ai

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing
type MockIPGeoDatabase struct {
	mock.Mock
}

func (m *MockIPGeoDatabase) GetCountry(ip net.IP) (string, error) {
	args := m.Called(ip)
	return args.String(0), args.Error(1)
}

func (m *MockIPGeoDatabase) GetASN(ip net.IP) (string, error) {
	args := m.Called(ip)
	return args.String(0), args.Error(1)
}

func (m *MockIPGeoDatabase) GetDistance(ip1, ip2 net.IP) (float64, error) {
	args := m.Called(ip1, ip2)
	return args.Get(0).(float64), args.Error(1)
}

type MockDomainAgeDatabase struct {
	mock.Mock
}

func (m *MockDomainAgeDatabase) GetDomainAge(domain string) (int, error) {
	args := m.Called(domain)
	return args.Int(0), args.Error(1)
}

func (m *MockDomainAgeDatabase) GetRegistrar(domain string) (string, error) {
	args := m.Called(domain)
	return args.String(0), args.Error(1)
}

type MockReputationDatabase struct {
	mock.Mock
}

func (m *MockReputationDatabase) GetIPReputation(ip net.IP) (float64, error) {
	args := m.Called(ip)
	return args.Get(0).(float64), args.Error(1)
}

func (m *MockReputationDatabase) GetDomainReputation(domain string) (float64, error) {
	args := m.Called(domain)
	return args.Get(0).(float64), args.Error(1)
}

func (m *MockReputationDatabase) GetASNReputation(asn string) (float64, error) {
	args := m.Called(asn)
	return args.Get(0).(float64), args.Error(1)
}

func TestAdvancedFeatureExtractor_ExtractAdvancedFeatures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Setup mocks
	ipGeoDB := &MockIPGeoDatabase{}
	domainAgeDB := &MockDomainAgeDatabase{}
	reputationDB := &MockReputationDatabase{}
	
	extractor := NewAdvancedFeatureExtractor(logger, ipGeoDB, domainAgeDB, reputationDB)
	
	// Setup mock expectations
	testIP := net.ParseIP("192.168.1.1")
	ipGeoDB.On("GetCountry", testIP).Return("US", nil)
	ipGeoDB.On("GetASN", testIP).Return("AS12345 Test ISP", nil)
	reputationDB.On("GetIPReputation", testIP).Return(75.0, nil)
	reputationDB.On("GetASNReputation", "AS12345 Test ISP").Return(80.0, nil)
	reputationDB.On("GetDomainReputation", "example.com").Return(90.0, nil)
	domainAgeDB.On("GetDomainAge", "example.com").Return(365, nil)
	domainAgeDB.On("GetRegistrar", "example.com").Return("GoDaddy", nil)
	
	request := &ThreatAnalysisRequest{
		RequestID:     "test-1",
		SourceIP:      testIP,
		URL:           "https://example.com/path/to/resource?param=value",
		Method:        "GET",
		ContentType:   "text/html",
		ContentLength: 1024,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
		},
		Body:      []byte("test content"),
		Timestamp: time.Now(),
	}
	
	features, err := extractor.ExtractAdvancedFeatures(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, features)
	
	// Verify basic features are present
	assert.Greater(t, features.URLLength, 0.0)
	assert.Greater(t, features.URLEntropy, 0.0)
	
	// Verify advanced features are present
	assert.Equal(t, 75.0, features.IPReputation)
	assert.Equal(t, 80.0, features.ASNReputation)
	assert.Equal(t, 365.0, features.DomainAge)
	
	// Verify additional features
	assert.Contains(t, features.Features, "domain_reputation")
	assert.Equal(t, 90.0, features.Features["domain_reputation"])
	assert.Contains(t, features.Features, "source_country")
	assert.Contains(t, features.Features, "domain_length")
	assert.Contains(t, features.Features, "domain_entropy")
	
	// Verify all mocks were called
	ipGeoDB.AssertExpectations(t)
	domainAgeDB.AssertExpectations(t)
	reputationDB.AssertExpectations(t)
}

func TestAdvancedFeatureExtractor_DGADetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "normal domain",
			domain:   "google.com",
			expected: false,
		},
		{
			name:     "DGA-like domain",
			domain:   "xkjdhfkjsdhfkjsdhf.com",
			expected: true,
		},
		{
			name:     "short domain",
			domain:   "a.com",
			expected: false,
		},
		{
			name:     "consonant heavy",
			domain:   "bcdfghjklmnpqrstvwxyz.com",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.isDGADomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_HomographDetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "normal latin domain",
			domain:   "example.com",
			expected: false,
		},
		{
			name:     "mixed script domain",
			domain:   "exаmple.com", // Contains Cyrillic 'а'
			expected: true,
		},
		{
			name:     "pure cyrillic",
			domain:   "пример.com",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.hasHomographChars(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_ContentAnalysis(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		content  []byte
		checkFunc func(*AdvancedFeatureExtractor, []byte) bool
		expected bool
	}{
		{
			name:      "base64 content",
			content:   []byte("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U="),
			checkFunc: (*AdvancedFeatureExtractor).hasBase64Content,
			expected:  true,
		},
		{
			name:      "hex content",
			content:   []byte("48656c6c6f20576f726c6421205468697320697320612074657374206d657373616765"),
			checkFunc: (*AdvancedFeatureExtractor).hasHexContent,
			expected:  true,
		},
		{
			name:      "normal content",
			content:   []byte("Hello World! This is a test message"),
			checkFunc: (*AdvancedFeatureExtractor).hasBase64Content,
			expected:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.checkFunc(extractor, tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_SQLInjectionDetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "normal content",
			content:  "Hello World",
			expected: false,
		},
		{
			name:     "SQL injection",
			content:  "'; DROP TABLE users; --",
			expected: true,
		},
		{
			name:     "UNION attack",
			content:  "1 UNION SELECT * FROM passwords",
			expected: true,
		},
		{
			name:     "case insensitive",
			content:  "Select * from users",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.hasSQLKeywords(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_PathTraversalDetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "normal path",
			path:     "/api/v1/users",
			expected: false,
		},
		{
			name:     "path traversal",
			path:     "/api/../../../etc/passwd",
			expected: true,
		},
		{
			name:     "encoded traversal",
			path:     "/api/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expected: true,
		},
		{
			name:     "windows traversal",
			path:     "/api/..\\..\\windows\\system32",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.hasPathTraversal(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_XSSDetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "normal query",
			query:    "search=hello+world",
			expected: false,
		},
		{
			name:     "script tag",
			query:    "input=<script>alert('xss')</script>",
			expected: true,
		},
		{
			name:     "javascript protocol",
			query:    "url=javascript:alert('xss')",
			expected: true,
		},
		{
			name:     "event handler",
			query:    "img=<img onerror=alert('xss')>",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.hasXSSPatterns(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdvancedFeatureExtractor_CyclicalEncoding(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	// Test hour encoding (0-23)
	result := extractor.cyclicalEncode(12, 24) // Noon
	assert.InDelta(t, 1.0, result[0], 0.1)     // sin should be ~1 at noon
	assert.InDelta(t, 0.5, result[1], 0.1)     // cos should be ~0 at noon
	
	// Test day encoding (0-6)
	result = extractor.cyclicalEncode(0, 7) // Sunday
	assert.InDelta(t, 0.5, result[0], 0.1)  // sin should be ~0 at start
	assert.InDelta(t, 1.0, result[1], 0.1)  // cos should be ~1 at start
}

func TestAdvancedFeatureExtractor_HighRiskCountry(t *testing.T) {
	logger := logrus.New()
	extractor := NewAdvancedFeatureExtractor(logger, nil, nil, nil)
	
	tests := []struct {
		name     string
		country  string
		expected bool
	}{
		{"US", "US", false},
		{"China", "CN", true},
		{"Russia", "RU", true},
		{"Germany", "DE", false},
		{"North Korea", "KP", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.isHighRiskCountry(tt.country)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultFeatureExtractor_NormalizationAndWeights(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	extractor := NewDefaultFeatureExtractor(logger)
	
	// Test normalization
	features := &FeatureVector{
		URLLength:    200,  // Should normalize to (200-0)/(2000-0) = 0.1
		URLEntropy:   4,    // Should normalize to (4-0)/(8-0) = 0.5
		ContentLength: 50000, // Should normalize to (50000-0)/(1000000-0) = 0.05
		Features:     make(map[string]float64),
	}
	
	normalized := extractor.NormalizeFeatures(features)
	
	assert.InDelta(t, 0.1, normalized.URLLength, 0.01)
	assert.InDelta(t, 0.5, normalized.URLEntropy, 0.01)
	assert.InDelta(t, 0.05, normalized.ContentLength, 0.01)
	
	// Test feature weights
	weighted := extractor.ApplyFeatureWeights(normalized)
	
	// URL entropy has weight 0.8, so 0.5 * 0.8 = 0.4
	assert.InDelta(t, 0.4, weighted.URLEntropy, 0.01)
	
	// IP reputation has weight 1.0, so should remain unchanged
	features.IPReputation = 75
	normalized = extractor.NormalizeFeatures(features)
	weighted = extractor.ApplyFeatureWeights(normalized)
	assert.Equal(t, normalized.IPReputation, weighted.IPReputation)
}

func TestFeatureVector_ToMap(t *testing.T) {
	features := &FeatureVector{
		URLLength:    100,
		URLEntropy:   4.5,
		ContentLength: 1024,
		Features: map[string]float64{
			"custom_feature": 0.8,
			"another_feature": 1.2,
		},
	}
	
	featureMap := features.ToMap()
	
	assert.Equal(t, 100.0, featureMap["url_length"])
	assert.Equal(t, 4.5, featureMap["url_entropy"])
	assert.Equal(t, 1024.0, featureMap["content_length"])
	assert.Equal(t, 0.8, featureMap["custom_feature"])
	assert.Equal(t, 1.2, featureMap["another_feature"])
	
	// Verify all expected features are present
	expectedFeatures := []string{
		"url_length", "url_entropy", "domain_age", "subdomain_count",
		"path_depth", "query_param_count", "content_length", "header_count",
		"user_agent_entropy", "request_frequency", "time_of_day", "day_of_week",
		"session_duration", "ip_reputation", "geo_distance", "asn_reputation",
		"previous_violations", "account_age", "trust_score",
	}
	
	for _, feature := range expectedFeatures {
		assert.Contains(t, featureMap, feature)
	}
}