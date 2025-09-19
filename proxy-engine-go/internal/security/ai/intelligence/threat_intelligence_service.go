package intelligence

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
	"github.com/sirupsen/logrus"
)

// DefaultThreatIntelligenceService implements the ThreatIntelligenceService interface
type DefaultThreatIntelligenceService struct {
	storage       ai.AIStorage
	feedProviders []ThreatFeedProvider
	patterns      map[string]*ai.ThreatPattern
	ipReputations map[string]*ai.IPThreatReputation
	domainReps    map[string]*ai.DomainThreatReputation
	config        *ThreatIntelligenceConfig
	logger        *logrus.Logger
	mu            sync.RWMutex
}

// ThreatFeedProvider defines interface for threat intelligence feed providers
type ThreatFeedProvider interface {
	GetName() string
	GetThreatPatterns(ctx context.Context) ([]*ai.ThreatPattern, error)
	GetIPReputations(ctx context.Context, ips []net.IP) ([]*ai.IPThreatReputation, error)
	GetDomainReputations(ctx context.Context, domains []string) ([]*ai.DomainThreatReputation, error)
	IsEnabled() bool
	GetLastUpdate() time.Time
}

// ThreatIntelligenceConfig holds configuration for threat intelligence
type ThreatIntelligenceConfig struct {
	EnabledFeeds        []string      `json:"enabled_feeds"`
	UpdateInterval      time.Duration `json:"update_interval"`
	CacheTimeout        time.Duration `json:"cache_timeout"`
	MinConfidenceScore  float64       `json:"min_confidence_score"`
	MaxPatternsPerFeed  int           `json:"max_patterns_per_feed"`
	EnableIPReputation  bool          `json:"enable_ip_reputation"`
	EnableDomainRep     bool          `json:"enable_domain_reputation"`
	EnablePatternMatch  bool          `json:"enable_pattern_matching"`
}

// NewDefaultThreatIntelligenceService creates a new threat intelligence service
func NewDefaultThreatIntelligenceService(storage ai.AIStorage, logger *logrus.Logger) *DefaultThreatIntelligenceService {
	service := &DefaultThreatIntelligenceService{
		storage:       storage,
		feedProviders: make([]ThreatFeedProvider, 0),
		patterns:      make(map[string]*ai.ThreatPattern),
		ipReputations: make(map[string]*ai.IPThreatReputation),
		domainReps:    make(map[string]*ai.DomainThreatReputation),
		config:        getDefaultThreatIntelligenceConfig(),
		logger:        logger,
	}
	
	// Initialize with default feed providers
	service.initializeDefaultProviders()
	
	return service
}

// GetThreatIntelligence retrieves threat intelligence for a query
func (tis *DefaultThreatIntelligenceService) GetThreatIntelligence(ctx context.Context, query *ai.ThreatQuery) (*ai.ThreatIntelligence, error) {
	intelligence := &ai.ThreatIntelligence{
		Query:     query,
		IsThreat:  false,
		Patterns:  make([]*ai.ThreatPattern, 0),
		Sources:   make([]string, 0),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}
	
	switch query.Type {
	case "ip":
		return tis.getIPThreatIntelligence(ctx, query, intelligence)
	case "domain":
		return tis.getDomainThreatIntelligence(ctx, query, intelligence)
	case "url":
		return tis.getURLThreatIntelligence(ctx, query, intelligence)
	case "hash":
		return tis.getHashThreatIntelligence(ctx, query, intelligence)
	default:
		return nil, fmt.Errorf("unsupported query type: %s", query.Type)
	}
}

// getIPThreatIntelligence gets threat intelligence for an IP address
func (tis *DefaultThreatIntelligenceService) getIPThreatIntelligence(ctx context.Context, query *ai.ThreatQuery, intelligence *ai.ThreatIntelligence) (*ai.ThreatIntelligence, error) {
	if !tis.config.EnableIPReputation {
		return intelligence, nil
	}
	
	ip := net.ParseIP(query.Value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", query.Value)
	}
	
	// Check cache first
	tis.mu.RLock()
	if reputation, exists := tis.ipReputations[query.Value]; exists {
		tis.mu.RUnlock()
		
		if reputation.Reputation.Score < 50 { // Threshold for malicious
			intelligence.IsThreat = true
			intelligence.Confidence = (100 - reputation.Reputation.Score) / 100
			intelligence.ThreatType = ai.ThreatTypeSuspicious
			intelligence.Sources = reputation.Reputation.Sources
			
			// Create threat pattern
			pattern := &ai.ThreatPattern{
				ID:          fmt.Sprintf("ip-reputation-%s", query.Value),
				Name:        "Malicious IP Reputation",
				Type:        ai.ThreatTypeSuspicious,
				Level:       tis.calculateThreatLevel(intelligence.Confidence),
				Description: fmt.Sprintf("IP %s has poor reputation score: %.1f", query.Value, reputation.Reputation.Score),
				Confidence:  intelligence.Confidence,
				Sources:     reputation.Reputation.Sources,
				FirstSeen:   reputation.Reputation.LastUpdated,
				LastSeen:    time.Now(),
				Count:       1,
			}
			intelligence.Patterns = append(intelligence.Patterns, pattern)
		}
		
		intelligence.Reputation = reputation.Reputation
		return intelligence, nil
	}
	tis.mu.RUnlock()
	
	// Query feed providers
	for _, provider := range tis.feedProviders {
		if !provider.IsEnabled() || !tis.isFeedEnabled(provider.GetName()) {
			continue
		}
		
		reputations, err := provider.GetIPReputations(ctx, []net.IP{ip})
		if err != nil {
			tis.logger.Warnf("Failed to get IP reputation from %s: %v", provider.GetName(), err)
			continue
		}
		
		for _, reputation := range reputations {
			if reputation.IP.Equal(ip) {
				// Cache the reputation
				tis.mu.Lock()
				tis.ipReputations[query.Value] = reputation
				tis.mu.Unlock()
				
				intelligence.Sources = append(intelligence.Sources, provider.GetName())
				
				if reputation.Reputation.Score < 50 {
					intelligence.IsThreat = true
					intelligence.Confidence = (100 - reputation.Reputation.Score) / 100
					intelligence.ThreatType = ai.ThreatTypeSuspicious
				}
				
				intelligence.Reputation = reputation.Reputation
				break
			}
		}
	}
	
	return intelligence, nil
}

// getDomainThreatIntelligence gets threat intelligence for a domain
func (tis *DefaultThreatIntelligenceService) getDomainThreatIntelligence(ctx context.Context, query *ai.ThreatQuery, intelligence *ai.ThreatIntelligence) (*ai.ThreatIntelligence, error) {
	if !tis.config.EnableDomainRep {
		return intelligence, nil
	}
	
	domain := strings.ToLower(query.Value)
	
	// Check cache first
	tis.mu.RLock()
	if reputation, exists := tis.domainReps[domain]; exists {
		tis.mu.RUnlock()
		
		if reputation.Reputation.Score < 50 {
			intelligence.IsThreat = true
			intelligence.Confidence = (100 - reputation.Reputation.Score) / 100
			intelligence.ThreatType = tis.getDomainThreatType(reputation.Reputation.ThreatTypes)
			intelligence.Sources = reputation.Reputation.Sources
		}
		
		intelligence.Reputation = reputation.Reputation
		return intelligence, nil
	}
	tis.mu.RUnlock()
	
	// Query feed providers
	for _, provider := range tis.feedProviders {
		if !provider.IsEnabled() || !tis.isFeedEnabled(provider.GetName()) {
			continue
		}
		
		reputations, err := provider.GetDomainReputations(ctx, []string{domain})
		if err != nil {
			tis.logger.Warnf("Failed to get domain reputation from %s: %v", provider.GetName(), err)
			continue
		}
		
		for _, reputation := range reputations {
			if reputation.Domain == domain {
				// Cache the reputation
				tis.mu.Lock()
				tis.domainReps[domain] = reputation
				tis.mu.Unlock()
				
				intelligence.Sources = append(intelligence.Sources, provider.GetName())
				
				if reputation.Reputation.Score < 50 {
					intelligence.IsThreat = true
					intelligence.Confidence = (100 - reputation.Reputation.Score) / 100
					intelligence.ThreatType = tis.getDomainThreatType(reputation.Reputation.ThreatTypes)
				}
				
				intelligence.Reputation = reputation.Reputation
				break
			}
		}
	}
	
	return intelligence, nil
}

// getURLThreatIntelligence gets threat intelligence for a URL
func (tis *DefaultThreatIntelligenceService) getURLThreatIntelligence(ctx context.Context, query *ai.ThreatQuery, intelligence *ai.ThreatIntelligence) (*ai.ThreatIntelligence, error) {
	// Extract domain from URL and check domain reputation
	domain := tis.extractDomainFromURL(query.Value)
	if domain != "" {
		domainQuery := &ai.ThreatQuery{
			Type:      "domain",
			Value:     domain,
			Context:   query.Context,
			Timestamp: query.Timestamp,
		}
		
		domainIntel, err := tis.getDomainThreatIntelligence(ctx, domainQuery, intelligence)
		if err != nil {
			return nil, err
		}
		
		intelligence = domainIntel
	}
	
	// Check URL patterns
	if tis.config.EnablePatternMatch {
		patterns := tis.checkURLPatterns(query.Value)
		intelligence.Patterns = append(intelligence.Patterns, patterns...)
		
		if len(patterns) > 0 {
			intelligence.IsThreat = true
			// Use highest confidence from patterns
			maxConfidence := 0.0
			for _, pattern := range patterns {
				if pattern.Confidence > maxConfidence {
					maxConfidence = pattern.Confidence
					intelligence.ThreatType = pattern.Type
				}
			}
			intelligence.Confidence = maxConfidence
		}
	}
	
	return intelligence, nil
}

// getHashThreatIntelligence gets threat intelligence for a file hash
func (tis *DefaultThreatIntelligenceService) getHashThreatIntelligence(ctx context.Context, query *ai.ThreatQuery, intelligence *ai.ThreatIntelligence) (*ai.ThreatIntelligence, error) {
	// Check hash patterns
	if tis.config.EnablePatternMatch {
		patterns := tis.checkHashPatterns(query.Value)
		intelligence.Patterns = append(intelligence.Patterns, patterns...)
		
		if len(patterns) > 0 {
			intelligence.IsThreat = true
			maxConfidence := 0.0
			for _, pattern := range patterns {
				if pattern.Confidence > maxConfidence {
					maxConfidence = pattern.Confidence
					intelligence.ThreatType = pattern.Type
				}
			}
			intelligence.Confidence = maxConfidence
		}
	}
	
	return intelligence, nil
}

// UpdateThreatFeeds updates threat intelligence from external feeds
func (tis *DefaultThreatIntelligenceService) UpdateThreatFeeds(ctx context.Context) error {
	tis.logger.Info("Updating threat intelligence feeds")
	
	var updatedFeeds int
	var totalPatterns int
	
	for _, provider := range tis.feedProviders {
		if !provider.IsEnabled() || !tis.isFeedEnabled(provider.GetName()) {
			continue
		}
		
		// Update patterns
		patterns, err := provider.GetThreatPatterns(ctx)
		if err != nil {
			tis.logger.Warnf("Failed to update patterns from %s: %v", provider.GetName(), err)
			continue
		}
		
		// Filter and store patterns
		validPatterns := tis.filterPatterns(patterns, provider.GetName())
		tis.storePatterns(validPatterns)
		
		totalPatterns += len(validPatterns)
		updatedFeeds++
		
		tis.logger.Infof("Updated %d patterns from %s", len(validPatterns), provider.GetName())
	}
	
	tis.logger.Infof("Threat feed update completed: %d feeds, %d total patterns", updatedFeeds, totalPatterns)
	return nil
}

// GetIPReputation gets reputation information for an IP
func (tis *DefaultThreatIntelligenceService) GetIPReputation(ctx context.Context, ip net.IP) (*ai.IPThreatReputation, error) {
	query := &ai.ThreatQuery{
		Type:      "ip",
		Value:     ip.String(),
		Timestamp: time.Now(),
	}
	
	intelligence, err := tis.GetThreatIntelligence(ctx, query)
	if err != nil {
		return nil, err
	}
	
	if intelligence.Reputation != nil {
		return &ai.IPThreatReputation{
			IP:         ip,
			Reputation: intelligence.Reputation,
		}, nil
	}
	
	// Return default reputation if not found
	return &ai.IPThreatReputation{
		IP: ip,
		Reputation: &ai.ThreatReputation{
			Score:       75.0, // Neutral score
			Category:    "unknown",
			Sources:     []string{},
			LastUpdated: time.Now(),
		},
	}, nil
}

// GetDomainReputation gets reputation information for a domain
func (tis *DefaultThreatIntelligenceService) GetDomainReputation(ctx context.Context, domain string) (*ai.DomainThreatReputation, error) {
	query := &ai.ThreatQuery{
		Type:      "domain",
		Value:     domain,
		Timestamp: time.Now(),
	}
	
	intelligence, err := tis.GetThreatIntelligence(ctx, query)
	if err != nil {
		return nil, err
	}
	
	if intelligence.Reputation != nil {
		return &ai.DomainThreatReputation{
			Domain:     domain,
			Reputation: intelligence.Reputation,
		}, nil
	}
	
	// Return default reputation if not found
	return &ai.DomainThreatReputation{
		Domain: domain,
		Reputation: &ai.ThreatReputation{
			Score:       75.0, // Neutral score
			Category:    "unknown",
			Sources:     []string{},
			LastUpdated: time.Now(),
		},
	}, nil
}

// CheckThreatPatterns checks if request matches known threat patterns
func (tis *DefaultThreatIntelligenceService) CheckThreatPatterns(ctx context.Context, request *ai.ThreatAnalysisRequest) ([]*ai.ThreatPattern, error) {
	var matchedPatterns []*ai.ThreatPattern
	
	if !tis.config.EnablePatternMatch {
		return matchedPatterns, nil
	}
	
	tis.mu.RLock()
	defer tis.mu.RUnlock()
	
	for _, pattern := range tis.patterns {
		if tis.matchesPattern(request, pattern) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}
	
	return matchedPatterns, nil
}

// RegisterFeedProvider registers a new threat feed provider
func (tis *DefaultThreatIntelligenceService) RegisterFeedProvider(provider ThreatFeedProvider) {
	tis.feedProviders = append(tis.feedProviders, provider)
	tis.logger.Infof("Registered threat feed provider: %s", provider.GetName())
}

// Helper methods

func (tis *DefaultThreatIntelligenceService) initializeDefaultProviders() {
	// Register default providers
	malwareFeed := NewMalwareDomainsFeed(tis.logger)
	phishingFeed := NewPhishingDomainsFeed(tis.logger)
	
	tis.RegisterFeedProvider(malwareFeed)
	tis.RegisterFeedProvider(phishingFeed)
}

func (tis *DefaultThreatIntelligenceService) isFeedEnabled(feedName string) bool {
	for _, enabled := range tis.config.EnabledFeeds {
		if enabled == feedName {
			return true
		}
	}
	return len(tis.config.EnabledFeeds) == 0 // If no specific feeds enabled, enable all
}

func (tis *DefaultThreatIntelligenceService) calculateThreatLevel(confidence float64) ai.ThreatLevel {
	if confidence >= 0.9 {
		return ai.ThreatLevelCritical
	} else if confidence >= 0.7 {
		return ai.ThreatLevelHigh
	} else if confidence >= 0.5 {
		return ai.ThreatLevelMedium
	}
	return ai.ThreatLevelLow
}

func (tis *DefaultThreatIntelligenceService) getDomainThreatType(threatTypes []string) ai.ThreatType {
	for _, threatType := range threatTypes {
		switch strings.ToLower(threatType) {
		case "malware":
			return ai.ThreatTypeMalware
		case "phishing":
			return ai.ThreatTypePhishing
		case "botnet", "c2", "command_control":
			return ai.ThreatTypeCommandControl
		}
	}
	return ai.ThreatTypeSuspicious
}

func (tis *DefaultThreatIntelligenceService) extractDomainFromURL(url string) string {
	// Simple domain extraction - in production, use proper URL parsing
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	
	return strings.ToLower(url)
}

func (tis *DefaultThreatIntelligenceService) checkURLPatterns(url string) []*ai.ThreatPattern {
	var patterns []*ai.ThreatPattern
	
	// Check for suspicious URL patterns
	suspiciousPatterns := []struct {
		pattern     string
		threatType  ai.ThreatType
		confidence  float64
		description string
	}{
		{".tk/", ai.ThreatTypeSuspicious, 0.6, "Suspicious TLD (.tk)"},
		{".ml/", ai.ThreatTypeSuspicious, 0.6, "Suspicious TLD (.ml)"},
		{"bit.ly/", ai.ThreatTypeSuspicious, 0.4, "URL shortener"},
		{"tinyurl.com/", ai.ThreatTypeSuspicious, 0.4, "URL shortener"},
		{"phishing", ai.ThreatTypePhishing, 0.8, "Phishing keyword in URL"},
		{"malware", ai.ThreatTypeMalware, 0.8, "Malware keyword in URL"},
	}
	
	urlLower := strings.ToLower(url)
	for _, sp := range suspiciousPatterns {
		if strings.Contains(urlLower, sp.pattern) {
			pattern := &ai.ThreatPattern{
				ID:          fmt.Sprintf("url-pattern-%s", sp.pattern),
				Name:        fmt.Sprintf("URL Pattern: %s", sp.description),
				Type:        sp.threatType,
				Level:       tis.calculateThreatLevel(sp.confidence),
				Description: sp.description,
				Confidence:  sp.confidence,
				Sources:     []string{"internal_patterns"},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Count:       1,
			}
			patterns = append(patterns, pattern)
		}
	}
	
	return patterns
}

func (tis *DefaultThreatIntelligenceService) checkHashPatterns(hash string) []*ai.ThreatPattern {
	// Placeholder for hash-based threat detection
	// In production, this would check against known malware hashes
	return []*ai.ThreatPattern{}
}

func (tis *DefaultThreatIntelligenceService) filterPatterns(patterns []*ai.ThreatPattern, source string) []*ai.ThreatPattern {
	var filtered []*ai.ThreatPattern
	
	for _, pattern := range patterns {
		if pattern.Confidence >= tis.config.MinConfidenceScore {
			pattern.Sources = []string{source}
			filtered = append(filtered, pattern)
		}
	}
	
	// Limit patterns per feed
	if len(filtered) > tis.config.MaxPatternsPerFeed {
		filtered = filtered[:tis.config.MaxPatternsPerFeed]
	}
	
	return filtered
}

func (tis *DefaultThreatIntelligenceService) storePatterns(patterns []*ai.ThreatPattern) {
	tis.mu.Lock()
	defer tis.mu.Unlock()
	
	for _, pattern := range patterns {
		tis.patterns[pattern.ID] = pattern
	}
}

func (tis *DefaultThreatIntelligenceService) matchesPattern(request *ai.ThreatAnalysisRequest, pattern *ai.ThreatPattern) bool {
	// Simple pattern matching - in production, implement more sophisticated matching
	for _, indicator := range pattern.Indicators {
		if strings.Contains(strings.ToLower(request.URL), strings.ToLower(indicator)) {
			return true
		}
		if strings.Contains(strings.ToLower(request.UserAgent), strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func getDefaultThreatIntelligenceConfig() *ThreatIntelligenceConfig {
	return &ThreatIntelligenceConfig{
		EnabledFeeds:       []string{}, // Empty means all feeds enabled
		UpdateInterval:     1 * time.Hour,
		CacheTimeout:       24 * time.Hour,
		MinConfidenceScore: 0.5,
		MaxPatternsPerFeed: 10000,
		EnableIPReputation: true,
		EnableDomainRep:    true,
		EnablePatternMatch: true,
	}
}