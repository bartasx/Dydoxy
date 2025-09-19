package ai

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultFeatureExtractor_ExtractFeatures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	extractor := NewDefaultFeatureExtractor(logger)
	
	tests := []struct {
		name     string
		request  *ThreatAnalysisRequest
		validate func(t *testing.T, features *FeatureVector)
	}{
		{
			name: "basic URL features",
			request: &ThreatAnalysisRequest{
				RequestID:     "test-1",
				URL:           "https://example.com/path/to/resource?param1=value1&param2=value2",
				Method:        "GET",
				ContentType:   "text/html",
				ContentLength: 1024,
				UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				Headers: map[string]string{
					"Accept":          "text/html,application/xhtml+xml",
					"Accept-Language": "en-US,en;q=0.9",
					"Connection":      "keep-alive",
				},
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Greater(t, features.URLLength, 0.0)
				assert.Greater(t, features.URLEntropy, 0.0)
				assert.Equal(t, 1.0, features.SubdomainCount) // example.com has 1 dot
				assert.Equal(t, 3.0, features.PathDepth)      // 3 slashes in path
				assert.Equal(t, 2.0, features.QueryParamCount) // 2 query parameters
				assert.Equal(t, 1024.0, features.ContentLength)
				assert.Equal(t, 3.0, features.HeaderCount)
				assert.Greater(t, features.UserAgentEntropy, 0.0)
			},
		},
		{
			name: "suspicious URL with IP",
			request: &ThreatAnalysisRequest{
				RequestID: "test-2",
				URL:       "http://192.168.1.1/malicious/path",
				Method:    "POST",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["has_ip_in_url"])
				assert.Equal(t, 1.0, features.Features["is_post"])
			},
		},
		{
			name: "URL shortener detection",
			request: &ThreatAnalysisRequest{
				RequestID: "test-3",
				URL:       "https://bit.ly/abc123",
				Method:    "GET",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["url_shortener"])
			},
		},
		{
			name: "suspicious TLD",
			request: &ThreatAnalysisRequest{
				RequestID: "test-4",
				URL:       "https://malicious.tk/phishing",
				Method:    "GET",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["suspicious_tld"])
			},
		},
		{
			name: "bot user agent",
			request: &ThreatAnalysisRequest{
				RequestID: "test-5",
				URL:       "https://example.com/",
				UserAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["ua_is_bot"])
				assert.Equal(t, 0.0, features.Features["ua_is_browser"])
			},
		},
		{
			name: "mobile user agent",
			request: &ThreatAnalysisRequest{
				RequestID: "test-6",
				URL:       "https://example.com/",
				UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["ua_is_mobile"])
				assert.Equal(t, 1.0, features.Features["ua_is_browser"])
			},
		},
		{
			name: "suspicious user agent",
			request: &ThreatAnalysisRequest{
				RequestID: "test-7",
				URL:       "https://example.com/",
				UserAgent: "python-requests/2.25.1",
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["ua_suspicious"])
			},
		},
		{
			name: "temporal features",
			request: &ThreatAnalysisRequest{
				RequestID: "test-8",
				URL:       "https://example.com/",
				Timestamp: time.Date(2023, 12, 15, 14, 30, 0, 0, time.UTC), // Friday 2:30 PM
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 14.0, features.TimeOfDay)
				assert.Equal(t, 5.0, features.DayOfWeek) // Friday
				assert.Equal(t, 0.0, features.Features["is_weekend"])
				assert.Equal(t, 1.0, features.Features["is_business_hours"])
			},
		},
		{
			name: "weekend and night features",
			request: &ThreatAnalysisRequest{
				RequestID: "test-9",
				URL:       "https://example.com/",
				Timestamp: time.Date(2023, 12, 16, 23, 30, 0, 0, time.UTC), // Saturday 11:30 PM
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 23.0, features.TimeOfDay)
				assert.Equal(t, 6.0, features.DayOfWeek) // Saturday
				assert.Equal(t, 1.0, features.Features["is_weekend"])
				assert.Equal(t, 1.0, features.Features["is_night"])
				assert.Equal(t, 0.0, features.Features["is_business_hours"])
			},
		},
		{
			name: "X-Forwarded headers",
			request: &ThreatAnalysisRequest{
				RequestID: "test-10",
				URL:       "https://example.com/",
				Headers: map[string]string{
					"X-Forwarded-For":   "192.168.1.1",
					"X-Forwarded-Proto": "https",
					"User-Agent":        "Mozilla/5.0",
				},
				Timestamp: time.Now(),
			},
			validate: func(t *testing.T, features *FeatureVector) {
				assert.Equal(t, 1.0, features.Features["has_x_forwarded"])
				assert.Greater(t, features.Features["unusual_headers"], 0.0)
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features, err := extractor.ExtractFeatures(context.Background(), tt.request)
			require.NoError(t, err)
			require.NotNil(t, features)
			
			tt.validate(t, features)
		})
	}
}

func TestDefaultFeatureExtractor_ExtractBehavioralFeatures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	extractor := NewDefaultFeatureExtractor(logger)
	
	request := &RequestContext{
		SourceIP:      net.ParseIP("192.168.1.1"),
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Method:        "GET",
		Path:          "/api/v1/users",
		Headers:       map[string]string{"Accept": "application/json", "Authorization": "Bearer token"},
		ContentLength: 512,
		Timestamp:     time.Date(2023, 12, 15, 14, 30, 0, 0, time.UTC),
		UserID:        "user123",
	}
	
	features, err := extractor.ExtractBehavioralFeatures(context.Background(), "user123", request)
	require.NoError(t, err)
	require.NotNil(t, features)
	
	assert.Equal(t, 14.0, features["hour_of_day"])
	assert.Equal(t, 5.0, features["day_of_week"]) // Friday
	assert.Equal(t, 0.0, features["is_weekend"])
	assert.Equal(t, 512.0, features["content_length"])
	assert.Equal(t, 13.0, features["path_length"]) // "/api/v1/users"
	assert.Equal(t, 2.0, features["header_count"])
	assert.Greater(t, features["user_agent_entropy"], 0.0)
}

func TestDefaultFeatureExtractor_GetFeatureNames(t *testing.T) {
	logger := logrus.New()
	extractor := NewDefaultFeatureExtractor(logger)
	
	names := extractor.GetFeatureNames()
	
	assert.NotEmpty(t, names)
	assert.Contains(t, names, "url_length")
	assert.Contains(t, names, "url_entropy")
	assert.Contains(t, names, "content_length")
	assert.Contains(t, names, "time_of_day")
}

func TestDefaultFeatureExtractor_ValidateFeatures(t *testing.T) {
	logger := logrus.New()
	extractor := NewDefaultFeatureExtractor(logger)
	
	// Valid features
	validFeatures := &FeatureVector{
		URLLength:         100,
		URLEntropy:        4.5,
		DomainAge:         365,
		SubdomainCount:    2,
		PathDepth:         3,
		QueryParamCount:   1,
		ContentLength:     1024,
		HeaderCount:       5,
		UserAgentEntropy:  4.2,
		RequestFrequency:  10,
		TimeOfDay:         14,
		DayOfWeek:         5,
		SessionDuration:   300,
		IPReputation:      75,
		GeoDistance:       100,
		ASNReputation:     80,
		PreviousViolations: 0,
		AccountAge:        30,
		TrustScore:        85,
		Features:          make(map[string]float64),
	}
	
	err := extractor.ValidateFeatures(validFeatures)
	assert.NoError(t, err)
	
	// Invalid features (missing some fields)
	invalidFeatures := &FeatureVector{
		URLLength: 100,
		Features:  make(map[string]float64),
	}
	
	err = extractor.ValidateFeatures(invalidFeatures)
	assert.Error(t, err)
}

func TestCalculateEntropy(t *testing.T) {
	logger := logrus.New()
	extractor := NewDefaultFeatureExtractor(logger)
	
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0.0,
		},
		{
			name:     "single character",
			input:    "aaaa",
			expected: 0.0,
		},
		{
			name:     "uniform distribution",
			input:    "abcd",
			expected: 2.0,
		},
		{
			name:     "mixed string",
			input:    "hello world",
			expected: 3.273, // approximate
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := extractor.calculateEntropy(tt.input)
			if tt.expected == 0.0 {
				assert.Equal(t, tt.expected, entropy)
			} else {
				assert.InDelta(t, tt.expected, entropy, 0.1)
			}
		})
	}
}

func TestSuspiciousPatternDetection(t *testing.T) {
	logger := logrus.New()
	extractor := NewDefaultFeatureExtractor(logger)
	
	// Test IP in URL
	assert.True(t, extractor.hasIPInURL("192.168.1.1"))
	assert.True(t, extractor.hasIPInURL("10.0.0.1"))
	assert.False(t, extractor.hasIPInURL("example.com"))
	
	// Test suspicious TLD
	assert.True(t, extractor.hasSuspiciousTLD("malicious.tk"))
	assert.True(t, extractor.hasSuspiciousTLD("phishing.ml"))
	assert.False(t, extractor.hasSuspiciousTLD("example.com"))
	
	// Test URL shortener
	assert.True(t, extractor.isURLShortener("bit.ly"))
	assert.True(t, extractor.isURLShortener("tinyurl.com"))
	assert.False(t, extractor.isURLShortener("example.com"))
	
	// Test user agent patterns
	assert.True(t, extractor.isBrowserUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"))
	assert.True(t, extractor.isBotUserAgent("Googlebot/2.1 (+http://www.google.com/bot.html)"))
	assert.True(t, extractor.isMobileUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"))
	assert.True(t, extractor.isSuspiciousUserAgent("python-requests/2.25.1"))
	assert.True(t, extractor.isSuspiciousUserAgent("a")) // too short
}