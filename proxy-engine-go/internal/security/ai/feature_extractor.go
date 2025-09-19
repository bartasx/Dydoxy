package ai

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultFeatureExtractor implements the FeatureExtractor interface
type DefaultFeatureExtractor struct {
	logger           *logrus.Logger
	normalizationParams map[string]NormalizationParams
	featureWeights   map[string]float64
}

// NormalizationParams holds parameters for feature normalization
type NormalizationParams struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
}

// NewDefaultFeatureExtractor creates a new feature extractor
func NewDefaultFeatureExtractor(logger *logrus.Logger) *DefaultFeatureExtractor {
	extractor := &DefaultFeatureExtractor{
		logger:              logger,
		normalizationParams: make(map[string]NormalizationParams),
		featureWeights:      make(map[string]float64),
	}
	
	// Set default normalization parameters
	extractor.setDefaultNormalizationParams()
	
	// Set default feature weights
	extractor.setDefaultFeatureWeights()
	
	return extractor
}

// ExtractFeatures converts a threat analysis request to feature vector
func (fe *DefaultFeatureExtractor) ExtractFeatures(ctx context.Context, request *ThreatAnalysisRequest) (*FeatureVector, error) {
	features := &FeatureVector{
		Features: make(map[string]float64),
	}
	
	// Extract URL features
	if err := fe.extractURLFeatures(request.URL, features); err != nil {
		fe.logger.Warnf("Failed to extract URL features: %v", err)
	}
	
	// Extract content features
	fe.extractContentFeatures(request, features)
	
	// Extract temporal features
	fe.extractTemporalFeatures(request.Timestamp, features)
	
	// Extract header features
	fe.extractHeaderFeatures(request.Headers, features)
	
	// Extract user agent features
	if request.UserAgent != "" {
		fe.extractUserAgentFeatures(request.UserAgent, features)
	}
	
	return features, nil
}

// ExtractBehavioralFeatures extracts behavioral features for a subject
func (fe *DefaultFeatureExtractor) ExtractBehavioralFeatures(ctx context.Context, subject string, request *RequestContext) (map[string]float64, error) {
	features := make(map[string]float64)
	
	// Extract temporal behavioral features
	features["hour_of_day"] = float64(request.Timestamp.Hour())
	features["day_of_week"] = float64(request.Timestamp.Weekday())
	features["is_weekend"] = boolToFloat(request.Timestamp.Weekday() == time.Saturday || request.Timestamp.Weekday() == time.Sunday)
	
	// Extract request pattern features
	features["content_length"] = float64(request.ContentLength)
	features["path_length"] = float64(len(request.Path))
	features["header_count"] = float64(len(request.Headers))
	
	// Extract user agent features
	if request.UserAgent != "" {
		features["user_agent_length"] = float64(len(request.UserAgent))
		features["user_agent_entropy"] = fe.calculateEntropy(request.UserAgent)
	}
	
	return features, nil
}

// GetFeatureNames returns list of feature names
func (fe *DefaultFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"url_length", "url_entropy", "domain_age", "subdomain_count",
		"path_depth", "query_param_count", "content_length", "header_count",
		"user_agent_entropy", "request_frequency", "time_of_day", "day_of_week",
		"session_duration", "ip_reputation", "geo_distance", "asn_reputation",
		"previous_violations", "account_age", "trust_score",
	}
}

// ValidateFeatures validates feature vector completeness
func (fe *DefaultFeatureExtractor) ValidateFeatures(features *FeatureVector) error {
	requiredFeatures := fe.GetFeatureNames()
	
	for _, featureName := range requiredFeatures {
		if !fe.hasFeature(features, featureName) {
			return fmt.Errorf("missing required feature: %s", featureName)
		}
	}
	
	return nil
}

// extractURLFeatures extracts features from URL
func (fe *DefaultFeatureExtractor) extractURLFeatures(rawURL string, features *FeatureVector) error {
	if rawURL == "" {
		return nil
	}
	
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	
	// Basic URL features
	features.URLLength = float64(len(rawURL))
	features.URLEntropy = fe.calculateEntropy(rawURL)
	
	// Domain features
	if parsedURL.Host != "" {
		features.SubdomainCount = float64(strings.Count(parsedURL.Host, "."))
		// Domain age would require external lookup - set to 0 for now
		features.DomainAge = 0
	}
	
	// Path features
	if parsedURL.Path != "" {
		features.PathDepth = float64(strings.Count(parsedURL.Path, "/"))
	}
	
	// Query parameter features
	if parsedURL.RawQuery != "" {
		queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
		features.QueryParamCount = float64(len(queryParams))
	}
	
	// Additional URL analysis
	features.Features["has_ip_in_url"] = boolToFloat(fe.hasIPInURL(parsedURL.Host))
	features.Features["suspicious_tld"] = boolToFloat(fe.hasSuspiciousTLD(parsedURL.Host))
	features.Features["url_shortener"] = boolToFloat(fe.isURLShortener(parsedURL.Host))
	
	return nil
}

// extractContentFeatures extracts features from request content
func (fe *DefaultFeatureExtractor) extractContentFeatures(request *ThreatAnalysisRequest, features *FeatureVector) {
	features.ContentLength = float64(request.ContentLength)
	features.HeaderCount = float64(len(request.Headers))
	
	// Content type analysis
	if request.ContentType != "" {
		features.Features["is_json"] = boolToFloat(strings.Contains(request.ContentType, "application/json"))
		features.Features["is_xml"] = boolToFloat(strings.Contains(request.ContentType, "xml"))
		features.Features["is_form"] = boolToFloat(strings.Contains(request.ContentType, "form"))
	}
	
	// Method analysis
	features.Features["is_get"] = boolToFloat(request.Method == "GET")
	features.Features["is_post"] = boolToFloat(request.Method == "POST")
	features.Features["is_put"] = boolToFloat(request.Method == "PUT")
	features.Features["is_delete"] = boolToFloat(request.Method == "DELETE")
}

// extractTemporalFeatures extracts time-based features
func (fe *DefaultFeatureExtractor) extractTemporalFeatures(timestamp time.Time, features *FeatureVector) {
	features.TimeOfDay = float64(timestamp.Hour())
	features.DayOfWeek = float64(timestamp.Weekday())
	
	// Additional temporal features
	features.Features["is_weekend"] = boolToFloat(timestamp.Weekday() == time.Saturday || timestamp.Weekday() == time.Sunday)
	features.Features["is_business_hours"] = boolToFloat(timestamp.Hour() >= 9 && timestamp.Hour() <= 17)
	features.Features["is_night"] = boolToFloat(timestamp.Hour() >= 22 || timestamp.Hour() <= 6)
}

// extractHeaderFeatures extracts features from HTTP headers
func (fe *DefaultFeatureExtractor) extractHeaderFeatures(headers map[string]string, features *FeatureVector) {
	if headers == nil {
		return
	}
	
	// Common header presence
	features.Features["has_referer"] = boolToFloat(headers["Referer"] != "" || headers["referer"] != "")
	features.Features["has_accept_language"] = boolToFloat(headers["Accept-Language"] != "" || headers["accept-language"] != "")
	features.Features["has_accept_encoding"] = boolToFloat(headers["Accept-Encoding"] != "" || headers["accept-encoding"] != "")
	features.Features["has_connection"] = boolToFloat(headers["Connection"] != "" || headers["connection"] != "")
	
	// Suspicious header patterns
	features.Features["has_x_forwarded"] = boolToFloat(fe.hasXForwardedHeaders(headers))
	features.Features["unusual_headers"] = float64(fe.countUnusualHeaders(headers))
}

// extractUserAgentFeatures extracts features from user agent string
func (fe *DefaultFeatureExtractor) extractUserAgentFeatures(userAgent string, features *FeatureVector) {
	features.UserAgentEntropy = fe.calculateEntropy(userAgent)
	
	// User agent analysis
	features.Features["ua_length"] = float64(len(userAgent))
	features.Features["ua_is_browser"] = boolToFloat(fe.isBrowserUserAgent(userAgent))
	features.Features["ua_is_bot"] = boolToFloat(fe.isBotUserAgent(userAgent))
	features.Features["ua_is_mobile"] = boolToFloat(fe.isMobileUserAgent(userAgent))
	features.Features["ua_suspicious"] = boolToFloat(fe.isSuspiciousUserAgent(userAgent))
}

// Helper functions

// calculateEntropy calculates Shannon entropy of a string
func (fe *DefaultFeatureExtractor) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// hasIPInURL checks if URL contains IP address instead of domain
func (fe *DefaultFeatureExtractor) hasIPInURL(host string) bool {
	ipPattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	return ipPattern.MatchString(host)
}

// hasSuspiciousTLD checks for suspicious top-level domains
func (fe *DefaultFeatureExtractor) hasSuspiciousTLD(host string) bool {
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".bit", ".onion"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	return false
}

// isURLShortener checks if domain is a known URL shortener
func (fe *DefaultFeatureExtractor) isURLShortener(host string) bool {
	shorteners := []string{"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link"}
	for _, shortener := range shorteners {
		if strings.Contains(host, shortener) {
			return true
		}
	}
	return false
}

// hasXForwardedHeaders checks for X-Forwarded headers
func (fe *DefaultFeatureExtractor) hasXForwardedHeaders(headers map[string]string) bool {
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-forwarded") {
			return true
		}
	}
	return false
}

// countUnusualHeaders counts headers that are not commonly seen
func (fe *DefaultFeatureExtractor) countUnusualHeaders(headers map[string]string) int {
	commonHeaders := map[string]bool{
		"accept": true, "accept-encoding": true, "accept-language": true,
		"authorization": true, "cache-control": true, "connection": true,
		"content-length": true, "content-type": true, "cookie": true,
		"host": true, "referer": true, "user-agent": true,
	}
	
	unusualCount := 0
	for key := range headers {
		if !commonHeaders[strings.ToLower(key)] {
			unusualCount++
		}
	}
	
	return unusualCount
}

// isBrowserUserAgent checks if user agent appears to be from a browser
func (fe *DefaultFeatureExtractor) isBrowserUserAgent(ua string) bool {
	browsers := []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}
	for _, browser := range browsers {
		if strings.Contains(ua, browser) {
			return true
		}
	}
	return false
}

// isBotUserAgent checks if user agent appears to be from a bot
func (fe *DefaultFeatureExtractor) isBotUserAgent(ua string) bool {
	bots := []string{"bot", "crawler", "spider", "scraper", "curl", "wget"}
	uaLower := strings.ToLower(ua)
	for _, bot := range bots {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}
	return false
}

// isMobileUserAgent checks if user agent appears to be from a mobile device
func (fe *DefaultFeatureExtractor) isMobileUserAgent(ua string) bool {
	mobile := []string{"Mobile", "Android", "iPhone", "iPad", "Windows Phone"}
	for _, m := range mobile {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

// isSuspiciousUserAgent checks for suspicious user agent patterns
func (fe *DefaultFeatureExtractor) isSuspiciousUserAgent(ua string) bool {
	// Very short or very long user agents
	if len(ua) < 10 || len(ua) > 500 {
		return true
	}
	
	// Common suspicious patterns
	suspicious := []string{"python", "java", "perl", "ruby", "php", "libwww"}
	uaLower := strings.ToLower(ua)
	for _, s := range suspicious {
		if strings.Contains(uaLower, s) {
			return true
		}
	}
	
	return false
}

// hasFeature checks if a feature exists in the feature vector
func (fe *DefaultFeatureExtractor) hasFeature(features *FeatureVector, name string) bool {
	// Check direct fields
	switch name {
	case "url_length":
		return true
	case "url_entropy":
		return true
	case "domain_age":
		return true
	case "subdomain_count":
		return true
	case "path_depth":
		return true
	case "query_param_count":
		return true
	case "content_length":
		return true
	case "header_count":
		return true
	case "user_agent_entropy":
		return true
	case "request_frequency":
		return true
	case "time_of_day":
		return true
	case "day_of_week":
		return true
	case "session_duration":
		return true
	case "ip_reputation":
		return true
	case "geo_distance":
		return true
	case "asn_reputation":
		return true
	case "previous_violations":
		return true
	case "account_age":
		return true
	case "trust_score":
		return true
	}
	
	// Check additional features map
	_, exists := features.Features[name]
	return exists
}

// boolToFloat converts boolean to float64
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// setDefaultNormalizationParams sets default normalization parameters for features
func (fe *DefaultFeatureExtractor) setDefaultNormalizationParams() {
	fe.normalizationParams = map[string]NormalizationParams{
		"url_length":         {Min: 0, Max: 2000, Mean: 100, StdDev: 200},
		"url_entropy":        {Min: 0, Max: 8, Mean: 4, StdDev: 1.5},
		"domain_age":         {Min: 0, Max: 10000, Mean: 1000, StdDev: 2000},
		"subdomain_count":    {Min: 0, Max: 10, Mean: 2, StdDev: 1.5},
		"path_depth":         {Min: 0, Max: 20, Mean: 3, StdDev: 2},
		"query_param_count":  {Min: 0, Max: 50, Mean: 2, StdDev: 5},
		"content_length":     {Min: 0, Max: 1000000, Mean: 10000, StdDev: 50000},
		"header_count":       {Min: 0, Max: 50, Mean: 10, StdDev: 5},
		"user_agent_entropy": {Min: 0, Max: 8, Mean: 4.5, StdDev: 1},
		"request_frequency":  {Min: 0, Max: 1000, Mean: 10, StdDev: 50},
		"time_of_day":        {Min: 0, Max: 23, Mean: 12, StdDev: 6},
		"day_of_week":        {Min: 0, Max: 6, Mean: 3, StdDev: 2},
		"session_duration":   {Min: 0, Max: 86400, Mean: 1800, StdDev: 3600},
		"ip_reputation":      {Min: 0, Max: 100, Mean: 50, StdDev: 25},
		"geo_distance":       {Min: 0, Max: 20000, Mean: 5000, StdDev: 5000},
		"asn_reputation":     {Min: 0, Max: 100, Mean: 70, StdDev: 20},
		"previous_violations": {Min: 0, Max: 100, Mean: 1, StdDev: 5},
		"account_age":        {Min: 0, Max: 3650, Mean: 365, StdDev: 500},
		"trust_score":        {Min: 0, Max: 100, Mean: 75, StdDev: 15},
	}
}

// setDefaultFeatureWeights sets default weights for features based on importance
func (fe *DefaultFeatureExtractor) setDefaultFeatureWeights() {
	fe.featureWeights = map[string]float64{
		"url_length":         0.6,
		"url_entropy":        0.8,
		"domain_age":         0.7,
		"subdomain_count":    0.5,
		"path_depth":         0.4,
		"query_param_count":  0.3,
		"content_length":     0.5,
		"header_count":       0.4,
		"user_agent_entropy": 0.9,
		"request_frequency":  0.8,
		"time_of_day":        0.6,
		"day_of_week":        0.3,
		"session_duration":   0.5,
		"ip_reputation":      1.0,
		"geo_distance":       0.4,
		"asn_reputation":     0.8,
		"previous_violations": 1.0,
		"account_age":        0.6,
		"trust_score":        0.9,
	}
}

// NormalizeFeatures normalizes feature values using stored parameters
func (fe *DefaultFeatureExtractor) NormalizeFeatures(features *FeatureVector) *FeatureVector {
	normalized := &FeatureVector{
		Features: make(map[string]float64),
	}
	
	// Normalize direct fields
	normalized.URLLength = fe.normalizeValue("url_length", features.URLLength)
	normalized.URLEntropy = fe.normalizeValue("url_entropy", features.URLEntropy)
	normalized.DomainAge = fe.normalizeValue("domain_age", features.DomainAge)
	normalized.SubdomainCount = fe.normalizeValue("subdomain_count", features.SubdomainCount)
	normalized.PathDepth = fe.normalizeValue("path_depth", features.PathDepth)
	normalized.QueryParamCount = fe.normalizeValue("query_param_count", features.QueryParamCount)
	normalized.ContentLength = fe.normalizeValue("content_length", features.ContentLength)
	normalized.HeaderCount = fe.normalizeValue("header_count", features.HeaderCount)
	normalized.UserAgentEntropy = fe.normalizeValue("user_agent_entropy", features.UserAgentEntropy)
	normalized.RequestFrequency = fe.normalizeValue("request_frequency", features.RequestFrequency)
	normalized.TimeOfDay = fe.normalizeValue("time_of_day", features.TimeOfDay)
	normalized.DayOfWeek = fe.normalizeValue("day_of_week", features.DayOfWeek)
	normalized.SessionDuration = fe.normalizeValue("session_duration", features.SessionDuration)
	normalized.IPReputation = fe.normalizeValue("ip_reputation", features.IPReputation)
	normalized.GeoDistance = fe.normalizeValue("geo_distance", features.GeoDistance)
	normalized.ASNReputation = fe.normalizeValue("asn_reputation", features.ASNReputation)
	normalized.PreviousViolations = fe.normalizeValue("previous_violations", features.PreviousViolations)
	normalized.AccountAge = fe.normalizeValue("account_age", features.AccountAge)
	normalized.TrustScore = fe.normalizeValue("trust_score", features.TrustScore)
	
	// Normalize additional features
	for name, value := range features.Features {
		normalized.Features[name] = fe.normalizeValue(name, value)
	}
	
	return normalized
}

// normalizeValue normalizes a single feature value using min-max normalization
func (fe *DefaultFeatureExtractor) normalizeValue(featureName string, value float64) float64 {
	params, exists := fe.normalizationParams[featureName]
	if !exists {
		return value // Return original value if no normalization params
	}
	
	if params.Max <= params.Min {
		return value // Avoid division by zero
	}
	
	// Min-max normalization: (value - min) / (max - min)
	normalized := (value - params.Min) / (params.Max - params.Min)
	
	// Clamp to [0, 1] range
	if normalized < 0 {
		normalized = 0
	} else if normalized > 1 {
		normalized = 1
	}
	
	return normalized
}

// ApplyFeatureWeights applies importance weights to features
func (fe *DefaultFeatureExtractor) ApplyFeatureWeights(features *FeatureVector) *FeatureVector {
	weighted := &FeatureVector{
		Features: make(map[string]float64),
	}
	
	// Apply weights to direct fields
	weighted.URLLength = features.URLLength * fe.getFeatureWeight("url_length")
	weighted.URLEntropy = features.URLEntropy * fe.getFeatureWeight("url_entropy")
	weighted.DomainAge = features.DomainAge * fe.getFeatureWeight("domain_age")
	weighted.SubdomainCount = features.SubdomainCount * fe.getFeatureWeight("subdomain_count")
	weighted.PathDepth = features.PathDepth * fe.getFeatureWeight("path_depth")
	weighted.QueryParamCount = features.QueryParamCount * fe.getFeatureWeight("query_param_count")
	weighted.ContentLength = features.ContentLength * fe.getFeatureWeight("content_length")
	weighted.HeaderCount = features.HeaderCount * fe.getFeatureWeight("header_count")
	weighted.UserAgentEntropy = features.UserAgentEntropy * fe.getFeatureWeight("user_agent_entropy")
	weighted.RequestFrequency = features.RequestFrequency * fe.getFeatureWeight("request_frequency")
	weighted.TimeOfDay = features.TimeOfDay * fe.getFeatureWeight("time_of_day")
	weighted.DayOfWeek = features.DayOfWeek * fe.getFeatureWeight("day_of_week")
	weighted.SessionDuration = features.SessionDuration * fe.getFeatureWeight("session_duration")
	weighted.IPReputation = features.IPReputation * fe.getFeatureWeight("ip_reputation")
	weighted.GeoDistance = features.GeoDistance * fe.getFeatureWeight("geo_distance")
	weighted.ASNReputation = features.ASNReputation * fe.getFeatureWeight("asn_reputation")
	weighted.PreviousViolations = features.PreviousViolations * fe.getFeatureWeight("previous_violations")
	weighted.AccountAge = features.AccountAge * fe.getFeatureWeight("account_age")
	weighted.TrustScore = features.TrustScore * fe.getFeatureWeight("trust_score")
	
	// Apply weights to additional features
	for name, value := range features.Features {
		weighted.Features[name] = value * fe.getFeatureWeight(name)
	}
	
	return weighted
}

// getFeatureWeight returns the weight for a feature, defaulting to 1.0 if not found
func (fe *DefaultFeatureExtractor) getFeatureWeight(featureName string) float64 {
	if weight, exists := fe.featureWeights[featureName]; exists {
		return weight
	}
	return 1.0 // Default weight
}

// ToMap converts FeatureVector to map[string]float64 for ML model input
func (fv *FeatureVector) ToMap() map[string]float64 {
	result := make(map[string]float64)
	
	// Add direct fields
	result["url_length"] = fv.URLLength
	result["url_entropy"] = fv.URLEntropy
	result["domain_age"] = fv.DomainAge
	result["subdomain_count"] = fv.SubdomainCount
	result["path_depth"] = fv.PathDepth
	result["query_param_count"] = fv.QueryParamCount
	result["content_length"] = fv.ContentLength
	result["header_count"] = fv.HeaderCount
	result["user_agent_entropy"] = fv.UserAgentEntropy
	result["request_frequency"] = fv.RequestFrequency
	result["time_of_day"] = fv.TimeOfDay
	result["day_of_week"] = fv.DayOfWeek
	result["session_duration"] = fv.SessionDuration
	result["ip_reputation"] = fv.IPReputation
	result["geo_distance"] = fv.GeoDistance
	result["asn_reputation"] = fv.ASNReputation
	result["previous_violations"] = fv.PreviousViolations
	result["account_age"] = fv.AccountAge
	result["trust_score"] = fv.TrustScore
	
	// Add additional features
	for name, value := range fv.Features {
		result[name] = value
	}
	
	return result
}

// UpdateNormalizationParams updates normalization parameters for a feature
func (fe *DefaultFeatureExtractor) UpdateNormalizationParams(featureName string, params NormalizationParams) {
	fe.normalizationParams[featureName] = params
	fe.logger.Debugf("Updated normalization params for feature %s", featureName)
}

// UpdateFeatureWeight updates the weight for a feature
func (fe *DefaultFeatureExtractor) UpdateFeatureWeight(featureName string, weight float64) {
	fe.featureWeights[featureName] = weight
	fe.logger.Debugf("Updated weight for feature %s to %.2f", featureName, weight)
}

// GetNormalizationParams returns normalization parameters for a feature
func (fe *DefaultFeatureExtractor) GetNormalizationParams(featureName string) (NormalizationParams, bool) {
	params, exists := fe.normalizationParams[featureName]
	return params, exists
}

// GetFeatureWeight returns the weight for a feature
func (fe *DefaultFeatureExtractor) GetFeatureWeight(featureName string) float64 {
	return fe.getFeatureWeight(featureName)
}