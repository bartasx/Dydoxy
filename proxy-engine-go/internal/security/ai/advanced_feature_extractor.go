package ai

import (
	"context"
	"crypto/md5"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// AdvancedFeatureExtractor provides advanced feature extraction capabilities
type AdvancedFeatureExtractor struct {
	*DefaultFeatureExtractor
	ipGeoDB      IPGeoDatabase
	domainAgeDB  DomainAgeDatabase
	reputationDB ReputationDatabase
}

// IPGeoDatabase interface for IP geolocation lookups
type IPGeoDatabase interface {
	GetCountry(ip net.IP) (string, error)
	GetASN(ip net.IP) (string, error)
	GetDistance(ip1, ip2 net.IP) (float64, error)
}

// DomainAgeDatabase interface for domain age lookups
type DomainAgeDatabase interface {
	GetDomainAge(domain string) (int, error)
	GetRegistrar(domain string) (string, error)
}

// ReputationDatabase interface for reputation lookups
type ReputationDatabase interface {
	GetIPReputation(ip net.IP) (float64, error)
	GetDomainReputation(domain string) (float64, error)
	GetASNReputation(asn string) (float64, error)
}

// NewAdvancedFeatureExtractor creates a new advanced feature extractor
func NewAdvancedFeatureExtractor(logger *logrus.Logger, ipGeoDB IPGeoDatabase, domainAgeDB DomainAgeDatabase, reputationDB ReputationDatabase) *AdvancedFeatureExtractor {
	return &AdvancedFeatureExtractor{
		DefaultFeatureExtractor: NewDefaultFeatureExtractor(logger),
		ipGeoDB:                 ipGeoDB,
		domainAgeDB:             domainAgeDB,
		reputationDB:            reputationDB,
	}
}

// ExtractAdvancedFeatures extracts advanced features with external data sources
func (afe *AdvancedFeatureExtractor) ExtractAdvancedFeatures(ctx context.Context, request *ThreatAnalysisRequest) (*FeatureVector, error) {
	// Start with basic features
	features, err := afe.ExtractFeatures(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to extract basic features: %w", err)
	}
	
	// Add advanced features
	if err := afe.addNetworkFeatures(ctx, request, features); err != nil {
		afe.logger.Warnf("Failed to add network features: %v", err)
	}
	
	if err := afe.addDomainFeatures(ctx, request, features); err != nil {
		afe.logger.Warnf("Failed to add domain features: %v", err)
	}
	
	if err := afe.addContentAnalysisFeatures(ctx, request, features); err != nil {
		afe.logger.Warnf("Failed to add content analysis features: %v", err)
	}
	
	if err := afe.addBehavioralFeatures(ctx, request, features); err != nil {
		afe.logger.Warnf("Failed to add behavioral features: %v", err)
	}
	
	return features, nil
}

// addNetworkFeatures adds network-related features
func (afe *AdvancedFeatureExtractor) addNetworkFeatures(ctx context.Context, request *ThreatAnalysisRequest, features *FeatureVector) error {
	if afe.ipGeoDB == nil || afe.reputationDB == nil {
		return nil // Skip if databases not available
	}
	
	// IP reputation
	if reputation, err := afe.reputationDB.GetIPReputation(request.SourceIP); err == nil {
		features.IPReputation = reputation
	}
	
	// Geographic features
	if country, err := afe.ipGeoDB.GetCountry(request.SourceIP); err == nil {
		features.Features["source_country"] = afe.countryToNumeric(country)
		features.Features["is_high_risk_country"] = boolToFloat(afe.isHighRiskCountry(country))
	}
	
	// ASN features
	if asn, err := afe.ipGeoDB.GetASN(request.SourceIP); err == nil {
		if asnReputation, err := afe.reputationDB.GetASNReputation(asn); err == nil {
			features.ASNReputation = asnReputation
		}
		features.Features["is_hosting_asn"] = boolToFloat(afe.isHostingASN(asn))
		features.Features["is_residential_asn"] = boolToFloat(afe.isResidentialASN(asn))
	}
	
	// Network distance (if we have a reference point)
	// This would require a reference IP, for now we'll use a placeholder
	features.GeoDistance = 0 // Would calculate actual distance
	
	return nil
}

// addDomainFeatures adds domain-related features
func (afe *AdvancedFeatureExtractor) addDomainFeatures(ctx context.Context, request *ThreatAnalysisRequest, features *FeatureVector) error {
	if request.URL == "" {
		return nil
	}
	
	parsedURL, err := url.Parse(request.URL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	
	domain := parsedURL.Host
	if domain == "" {
		return nil
	}
	
	// Remove port if present
	if colonIndex := strings.LastIndex(domain, ":"); colonIndex > 0 {
		domain = domain[:colonIndex]
	}
	
	// Domain age
	if afe.domainAgeDB != nil {
		if age, err := afe.domainAgeDB.GetDomainAge(domain); err == nil {
			features.DomainAge = float64(age)
		}
		
		if registrar, err := afe.domainAgeDB.GetRegistrar(domain); err == nil {
			features.Features["is_suspicious_registrar"] = boolToFloat(afe.isSuspiciousRegistrar(registrar))
		}
	}
	
	// Domain reputation
	if afe.reputationDB != nil {
		if reputation, err := afe.reputationDB.GetDomainReputation(domain); err == nil {
			features.Features["domain_reputation"] = reputation
		}
	}
	
	// Domain structure analysis
	features.Features["domain_length"] = float64(len(domain))
	features.Features["domain_entropy"] = afe.calculateEntropy(domain)
	features.Features["has_numbers_in_domain"] = boolToFloat(afe.hasNumbers(domain))
	features.Features["has_hyphens_in_domain"] = boolToFloat(strings.Contains(domain, "-"))
	features.Features["domain_level"] = float64(strings.Count(domain, ".") + 1)
	
	// Check for domain generation algorithm (DGA) patterns
	features.Features["likely_dga"] = boolToFloat(afe.isDGADomain(domain))
	
	// Homograph attack detection
	features.Features["has_homograph"] = boolToFloat(afe.hasHomographChars(domain))
	
	return nil
}

// addContentAnalysisFeatures adds content analysis features
func (afe *AdvancedFeatureExtractor) addContentAnalysisFeatures(ctx context.Context, request *ThreatAnalysisRequest, features *FeatureVector) error {
	// Analyze request body if present
	if len(request.Body) > 0 {
		features.Features["body_entropy"] = afe.calculateEntropy(string(request.Body))
		features.Features["has_base64"] = boolToFloat(afe.hasBase64Content(request.Body))
		features.Features["has_hex"] = boolToFloat(afe.hasHexContent(request.Body))
		features.Features["has_sql_keywords"] = boolToFloat(afe.hasSQLKeywords(string(request.Body)))
		features.Features["has_script_tags"] = boolToFloat(afe.hasScriptTags(string(request.Body)))
	}
	
	// Analyze URL path
	if parsedURL, err := url.Parse(request.URL); err == nil && parsedURL.Path != "" {
		features.Features["path_entropy"] = afe.calculateEntropy(parsedURL.Path)
		features.Features["has_traversal"] = boolToFloat(afe.hasPathTraversal(parsedURL.Path))
		features.Features["has_encoded_chars"] = boolToFloat(afe.hasEncodedChars(parsedURL.Path))
		features.Features["path_suspicious_keywords"] = float64(afe.countSuspiciousKeywords(parsedURL.Path))
	}
	
	// Analyze query parameters
	if parsedURL, err := url.Parse(request.URL); err == nil && parsedURL.RawQuery != "" {
		features.Features["query_entropy"] = afe.calculateEntropy(parsedURL.RawQuery)
		features.Features["query_has_sql"] = boolToFloat(afe.hasSQLKeywords(parsedURL.RawQuery))
		features.Features["query_has_xss"] = boolToFloat(afe.hasXSSPatterns(parsedURL.RawQuery))
	}
	
	return nil
}

// addBehavioralFeatures adds behavioral analysis features
func (afe *AdvancedFeatureExtractor) addBehavioralFeatures(ctx context.Context, request *ThreatAnalysisRequest, features *FeatureVector) error {
	// Time-based features
	now := request.Timestamp
	features.Features["hour_sin"] = afe.cyclicalEncode(float64(now.Hour()), 24)[0]
	features.Features["hour_cos"] = afe.cyclicalEncode(float64(now.Hour()), 24)[1]
	features.Features["day_sin"] = afe.cyclicalEncode(float64(now.Weekday()), 7)[0]
	features.Features["day_cos"] = afe.cyclicalEncode(float64(now.Weekday()), 7)[1]
	
	// Request pattern features
	features.Features["request_hash"] = afe.hashRequest(request)
	features.Features["user_agent_hash"] = afe.hashString(request.UserAgent)
	
	// Session-based features (would require session tracking)
	// For now, we'll use placeholder values
	features.SessionDuration = 0 // Would calculate from session data
	features.RequestFrequency = 0 // Would calculate from recent requests
	
	return nil
}

// Helper methods for advanced feature extraction

// countryToNumeric converts country code to numeric value
func (afe *AdvancedFeatureExtractor) countryToNumeric(country string) float64 {
	// Simple hash-based conversion
	hash := md5.Sum([]byte(country))
	return float64(hash[0]) / 255.0
}

// isHighRiskCountry checks if country is considered high risk
func (afe *AdvancedFeatureExtractor) isHighRiskCountry(country string) bool {
	highRiskCountries := []string{"CN", "RU", "KP", "IR", "SY"}
	for _, riskCountry := range highRiskCountries {
		if country == riskCountry {
			return true
		}
	}
	return false
}

// isHostingASN checks if ASN is associated with hosting providers
func (afe *AdvancedFeatureExtractor) isHostingASN(asn string) bool {
	hostingKeywords := []string{"hosting", "cloud", "server", "datacenter", "vps"}
	asnLower := strings.ToLower(asn)
	for _, keyword := range hostingKeywords {
		if strings.Contains(asnLower, keyword) {
			return true
		}
	}
	return false
}

// isResidentialASN checks if ASN is associated with residential ISPs
func (afe *AdvancedFeatureExtractor) isResidentialASN(asn string) bool {
	residentialKeywords := []string{"telecom", "broadband", "cable", "dsl", "fiber"}
	asnLower := strings.ToLower(asn)
	for _, keyword := range residentialKeywords {
		if strings.Contains(asnLower, keyword) {
			return true
		}
	}
	return false
}

// isSuspiciousRegistrar checks if domain registrar is suspicious
func (afe *AdvancedFeatureExtractor) isSuspiciousRegistrar(registrar string) bool {
	suspiciousRegistrars := []string{"namecheap", "godaddy", "1and1"} // Example list
	registrarLower := strings.ToLower(registrar)
	for _, suspicious := range suspiciousRegistrars {
		if strings.Contains(registrarLower, suspicious) {
			return true
		}
	}
	return false
}

// hasNumbers checks if string contains numbers
func (afe *AdvancedFeatureExtractor) hasNumbers(s string) bool {
	for _, char := range s {
		if char >= '0' && char <= '9' {
			return true
		}
	}
	return false
}

// isDGADomain checks if domain matches DGA patterns
func (afe *AdvancedFeatureExtractor) isDGADomain(domain string) bool {
	// Simple DGA detection based on entropy and length
	if len(domain) < 6 {
		return false
	}
	
	entropy := afe.calculateEntropy(domain)
	if entropy > 3.5 && len(domain) > 10 {
		return true
	}
	
	// Check for random-looking patterns
	consonantCount := 0
	vowelCount := 0
	vowels := "aeiou"
	
	for _, char := range strings.ToLower(domain) {
		if strings.ContainsRune(vowels, char) {
			vowelCount++
		} else if char >= 'a' && char <= 'z' {
			consonantCount++
		}
	}
	
	if consonantCount > 0 && vowelCount > 0 {
		ratio := float64(consonantCount) / float64(vowelCount)
		if ratio > 4 || ratio < 0.25 {
			return true
		}
	}
	
	return false
}

// hasHomographChars checks for homograph attack characters
func (afe *AdvancedFeatureExtractor) hasHomographChars(domain string) bool {
	// Check for mixed scripts or suspicious Unicode characters
	hasLatin := false
	hasCyrillic := false
	
	for _, char := range domain {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLatin = true
		} else if (char >= 0x0400 && char <= 0x04FF) { // Cyrillic range
			hasCyrillic = true
		}
	}
	
	return hasLatin && hasCyrillic
}

// hasBase64Content checks if content contains base64 encoded data
func (afe *AdvancedFeatureExtractor) hasBase64Content(data []byte) bool {
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	return base64Pattern.Match(data)
}

// hasHexContent checks if content contains hex encoded data
func (afe *AdvancedFeatureExtractor) hasHexContent(data []byte) bool {
	hexPattern := regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	return hexPattern.Match(data)
}

// hasSQLKeywords checks for SQL injection keywords
func (afe *AdvancedFeatureExtractor) hasSQLKeywords(content string) bool {
	sqlKeywords := []string{"union", "select", "insert", "update", "delete", "drop", "exec", "script"}
	contentLower := strings.ToLower(content)
	for _, keyword := range sqlKeywords {
		if strings.Contains(contentLower, keyword) {
			return true
		}
	}
	return false
}

// hasScriptTags checks for script tags
func (afe *AdvancedFeatureExtractor) hasScriptTags(content string) bool {
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>`)
	return scriptPattern.MatchString(content)
}

// hasPathTraversal checks for path traversal patterns
func (afe *AdvancedFeatureExtractor) hasPathTraversal(path string) bool {
	traversalPatterns := []string{"../", "..\\", "%2e%2e%2f", "%2e%2e%5c"}
	pathLower := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// hasEncodedChars checks for URL encoded characters
func (afe *AdvancedFeatureExtractor) hasEncodedChars(path string) bool {
	encodedPattern := regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	return encodedPattern.MatchString(path)
}

// countSuspiciousKeywords counts suspicious keywords in path
func (afe *AdvancedFeatureExtractor) countSuspiciousKeywords(path string) int {
	suspiciousKeywords := []string{"admin", "config", "backup", "test", "debug", "temp", "log"}
	pathLower := strings.ToLower(path)
	count := 0
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(pathLower, keyword) {
			count++
		}
	}
	return count
}

// hasXSSPatterns checks for XSS patterns
func (afe *AdvancedFeatureExtractor) hasXSSPatterns(query string) bool {
	xssPatterns := []string{"<script", "javascript:", "onerror=", "onload=", "alert("}
	queryLower := strings.ToLower(query)
	for _, pattern := range xssPatterns {
		if strings.Contains(queryLower, pattern) {
			return true
		}
	}
	return false
}

// cyclicalEncode encodes cyclical features (time, day) using sin/cos
func (afe *AdvancedFeatureExtractor) cyclicalEncode(value, maxValue float64) [2]float64 {
	angle := 2 * 3.14159 * value / maxValue
	return [2]float64{
		0.5 * (1 + math.Sin(angle)),
		0.5 * (1 + math.Cos(angle)),
	}
}

// hashRequest creates a hash of the request for deduplication
func (afe *AdvancedFeatureExtractor) hashRequest(request *ThreatAnalysisRequest) float64 {
	content := fmt.Sprintf("%s:%s:%s", request.Method, request.URL, request.UserAgent)
	return afe.hashString(content)
}

// hashString creates a numeric hash of a string
func (afe *AdvancedFeatureExtractor) hashString(s string) float64 {
	hash := md5.Sum([]byte(s))
	// Convert first 4 bytes to float64
	value := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
	return float64(value) / float64(^uint32(0))
}