package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// MalwareDomainsThreatFeed implements ThreatFeedProvider for malware domains
type MalwareDomainsThreatFeed struct {
	name        string
	url         string
	enabled     bool
	lastUpdate  time.Time
	httpClient  *http.Client
	logger      *logrus.Logger
}

// NewMalwareDomainsThreatFeed creates a new malware domains threat feed provider
func NewMalwareDomainsThreatFeed(logger *logrus.Logger) *MalwareDomainsThreatFeed {
	return &MalwareDomainsThreatFeed{
		name:    "MalwareDomains",
		url:     "https://malware-domains.com/files/domains.txt", // Example URL
		enabled: true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// GetName returns the name of the threat feed provider
func (f *MalwareDomainsThreatFeed) GetName() string {
	return f.name
}

// FetchEntries fetches entries from the threat feed
func (f *MalwareDomainsThreatFeed) FetchEntries(ctx context.Context) ([]*ListEntry, error) {
	f.logger.Infof("Fetching entries from %s", f.name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", f.url, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Read response body
	var domains []string
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&domains); err != nil {
		// If JSON fails, try to parse as plain text
		return f.parseTextResponse(resp)
	}
	
	// Convert to list entries
	var entries []*ListEntry
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		
		entry := &ListEntry{
			ID:        uuid.New().String(),
			Value:     domain,
			Type:      ListTypeBlacklist,
			Category:  string(CategoryMalware),
			Source:    string(SourceThreatFeed),
			Reason:    fmt.Sprintf("Malware domain from %s", f.name),
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata: map[string]interface{}{
				"provider": f.name,
				"feed_url": f.url,
			},
		}
		
		entries = append(entries, entry)
	}
	
	f.lastUpdate = time.Now()
	f.logger.Infof("Fetched %d entries from %s", len(entries), f.name)
	
	return entries, nil
}

// GetLastUpdate returns the timestamp of the last update
func (f *MalwareDomainsThreatFeed) GetLastUpdate() time.Time {
	return f.lastUpdate
}

// IsEnabled returns whether the provider is enabled
func (f *MalwareDomainsThreatFeed) IsEnabled() bool {
	return f.enabled
}

// SetEnabled enables or disables the provider
func (f *MalwareDomainsThreatFeed) SetEnabled(enabled bool) {
	f.enabled = enabled
}

// parseTextResponse parses plain text response (one domain per line)
func (f *MalwareDomainsThreatFeed) parseTextResponse(resp *http.Response) ([]*ListEntry, error) {
	// This is a simplified implementation
	// In reality, you'd read the response body and parse line by line
	return []*ListEntry{}, nil
}

// PhishingDomainsThreatFeed implements ThreatFeedProvider for phishing domains
type PhishingDomainsThreatFeed struct {
	name        string
	url         string
	enabled     bool
	lastUpdate  time.Time
	httpClient  *http.Client
	logger      *logrus.Logger
}

// NewPhishingDomainsThreatFeed creates a new phishing domains threat feed provider
func NewPhishingDomainsThreatFeed(logger *logrus.Logger) *PhishingDomainsThreatFeed {
	return &PhishingDomainsThreatFeed{
		name:    "PhishingDomains",
		url:     "https://phishing-domains.com/api/domains", // Example URL
		enabled: true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// GetName returns the name of the threat feed provider
func (f *PhishingDomainsThreatFeed) GetName() string {
	return f.name
}

// FetchEntries fetches entries from the threat feed
func (f *PhishingDomainsThreatFeed) FetchEntries(ctx context.Context) ([]*ListEntry, error) {
	f.logger.Infof("Fetching entries from %s", f.name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", f.url, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Parse JSON response
	var response struct {
		Domains []struct {
			Domain    string `json:"domain"`
			Detected  string `json:"detected"`
			Confidence float64 `json:"confidence"`
		} `json:"domains"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Convert to list entries
	var entries []*ListEntry
	for _, item := range response.Domains {
		if item.Domain == "" {
			continue
		}
		
		entry := &ListEntry{
			ID:        uuid.New().String(),
			Value:     item.Domain,
			Type:      ListTypeBlacklist,
			Category:  string(CategoryPhishing),
			Source:    string(SourceThreatFeed),
			Reason:    fmt.Sprintf("Phishing domain from %s (Confidence: %.2f)", f.name, item.Confidence),
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata: map[string]interface{}{
				"provider":   f.name,
				"feed_url":   f.url,
				"detected":   item.Detected,
				"confidence": item.Confidence,
			},
		}
		
		entries = append(entries, entry)
	}
	
	f.lastUpdate = time.Now()
	f.logger.Infof("Fetched %d entries from %s", len(entries), f.name)
	
	return entries, nil
}

// GetLastUpdate returns the timestamp of the last update
func (f *PhishingDomainsThreatFeed) GetLastUpdate() time.Time {
	return f.lastUpdate
}

// IsEnabled returns whether the provider is enabled
func (f *PhishingDomainsThreatFeed) IsEnabled() bool {
	return f.enabled
}

// SetEnabled enables or disables the provider
func (f *PhishingDomainsThreatFeed) SetEnabled(enabled bool) {
	f.enabled = enabled
}

// CustomThreatFeed allows for custom threat feed implementations
type CustomThreatFeed struct {
	name        string
	url         string
	enabled     bool
	lastUpdate  time.Time
	httpClient  *http.Client
	logger      *logrus.Logger
	parser      func([]byte) ([]*ListEntry, error)
}

// NewCustomThreatFeed creates a new custom threat feed provider
func NewCustomThreatFeed(name, url string, parser func([]byte) ([]*ListEntry, error), logger *logrus.Logger) *CustomThreatFeed {
	return &CustomThreatFeed{
		name:    name,
		url:     url,
		enabled: true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
		parser: parser,
	}
}

// GetName returns the name of the threat feed provider
func (f *CustomThreatFeed) GetName() string {
	return f.name
}

// FetchEntries fetches entries from the threat feed
func (f *CustomThreatFeed) FetchEntries(ctx context.Context) ([]*ListEntry, error) {
	f.logger.Infof("Fetching entries from %s", f.name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", f.url, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Read response body
	body := make([]byte, 0)
	buffer := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			body = append(body, buffer[:n]...)
		}
		if err != nil {
			break
		}
	}
	
	// Use custom parser
	entries, err := f.parser(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	f.lastUpdate = time.Now()
	f.logger.Infof("Fetched %d entries from %s", len(entries), f.name)
	
	return entries, nil
}

// GetLastUpdate returns the timestamp of the last update
func (f *CustomThreatFeed) GetLastUpdate() time.Time {
	return f.lastUpdate
}

// IsEnabled returns whether the provider is enabled
func (f *CustomThreatFeed) IsEnabled() bool {
	return f.enabled
}

// SetEnabled enables or disables the provider
func (f *CustomThreatFeed) SetEnabled(enabled bool) {
	f.enabled = enabled
}