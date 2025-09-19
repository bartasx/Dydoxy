package ddos

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TrafficAnalyzerImpl implements the TrafficAnalyzer interface
type TrafficAnalyzerImpl struct {
	storage       DDoSStorage
	logger        *logrus.Logger
	requestBuffer []*RequestContext
	bufferMu      sync.RWMutex
	bufferSize    int
	metrics       map[string]*TrafficMetrics
	metricsMu     sync.RWMutex
}

// NewTrafficAnalyzer creates a new traffic analyzer
func NewTrafficAnalyzer(storage DDoSStorage, logger *logrus.Logger) *TrafficAnalyzerImpl {
	analyzer := &TrafficAnalyzerImpl{
		storage:       storage,
		logger:        logger,
		requestBuffer: make([]*RequestContext, 0),
		bufferSize:    10000, // Keep last 10k requests in memory
		metrics:       make(map[string]*TrafficMetrics),
	}
	
	// Start background processing
	go analyzer.processMetrics()
	
	return analyzer
}

// RecordRequest records a request for analysis
func (ta *TrafficAnalyzerImpl) RecordRequest(ctx context.Context, request *RequestContext) error {
	ta.bufferMu.Lock()
	defer ta.bufferMu.Unlock()
	
	// Add to buffer
	ta.requestBuffer = append(ta.requestBuffer, request)
	
	// Maintain buffer size
	if len(ta.requestBuffer) > ta.bufferSize {
		// Remove oldest requests
		copy(ta.requestBuffer, ta.requestBuffer[len(ta.requestBuffer)-ta.bufferSize:])
		ta.requestBuffer = ta.requestBuffer[:ta.bufferSize]
	}
	
	return nil
}

// AnalyzeTraffic analyzes current traffic patterns
func (ta *TrafficAnalyzerImpl) AnalyzeTraffic(ctx context.Context, window time.Duration) (*TrafficMetrics, error) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	// Filter requests within the time window
	var recentRequests []*RequestContext
	for _, req := range ta.requestBuffer {
		if req.Timestamp.After(cutoff) {
			recentRequests = append(recentRequests, req)
		}
	}
	
	if len(recentRequests) == 0 {
		return &TrafficMetrics{
			Timestamp: now,
		}, nil
	}
	
	// Calculate metrics
	metrics := &TrafficMetrics{
		Timestamp: now,
	}
	
	// Basic counts
	totalRequests := int64(len(recentRequests))
	totalBytes := int64(0)
	uniqueIPs := make(map[string]bool)
	userAgents := make(map[string]int)
	paths := make(map[string]int)
	countries := make(map[string]int)
	errorCount := int64(0)
	totalResponseTime := float64(0)
	
	for _, req := range recentRequests {
		totalBytes += req.ContentLength
		uniqueIPs[req.SourceIP.String()] = true
		
		if req.UserAgent != "" {
			userAgents[req.UserAgent]++
		}
		
		if req.Path != "" {
			paths[req.Path]++
		}
		
		if req.Country != "" {
			countries[req.Country]++
		}
		
		// Simulate response time and error detection
		// In a real implementation, this would come from actual response data
		if req.Method == "POST" && req.ContentLength > 1024*1024 {
			errorCount++ // Simulate errors for large POST requests
		}
	}
	
	// Calculate rates
	windowSeconds := window.Seconds()
	metrics.RequestsPerSecond = float64(totalRequests) / windowSeconds
	metrics.BytesPerSecond = float64(totalBytes) / windowSeconds
	metrics.ConnectionsPerSecond = metrics.RequestsPerSecond // Simplified assumption
	metrics.ErrorRate = float64(errorCount) / float64(totalRequests)
	metrics.AverageResponseTime = totalResponseTime / float64(totalRequests)
	metrics.UniqueIPs = int64(len(uniqueIPs))
	
	// Get top user agents
	metrics.TopUserAgents = ta.getTopItems(userAgents, 10)
	
	// Get top paths
	metrics.TopPaths = ta.getTopItems(paths, 10)
	
	// Get geo distribution
	metrics.GeoDistribution = ta.getTopItems(countries, 10)
	
	// Cache metrics
	ta.metricsMu.Lock()
	ta.metrics[window.String()] = metrics
	ta.metricsMu.Unlock()
	
	return metrics, nil
}

// GetMetrics returns traffic metrics for a specific time window
func (ta *TrafficAnalyzerImpl) GetMetrics(ctx context.Context, start, end time.Time) ([]*TrafficMetrics, error) {
	return ta.storage.LoadTrafficMetrics(ctx, start, end)
}

// GetTopIPs returns top IPs by request count
func (ta *TrafficAnalyzerImpl) GetTopIPs(ctx context.Context, limit int, window time.Duration) ([]string, error) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	ipCounts := make(map[string]int)
	
	for _, req := range ta.requestBuffer {
		if req.Timestamp.After(cutoff) {
			ipCounts[req.SourceIP.String()]++
		}
	}
	
	// Sort by count
	type ipCount struct {
		ip    string
		count int
	}
	
	var ipList []ipCount
	for ip, count := range ipCounts {
		ipList = append(ipList, ipCount{ip: ip, count: count})
	}
	
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].count > ipList[j].count
	})
	
	// Return top IPs
	var topIPs []string
	for i, item := range ipList {
		if i >= limit {
			break
		}
		topIPs = append(topIPs, item.ip)
	}
	
	return topIPs, nil
}

// GetAnomalies detects traffic anomalies
func (ta *TrafficAnalyzerImpl) GetAnomalies(ctx context.Context, window time.Duration) ([]*TrafficMetrics, error) {
	// Get current metrics
	current, err := ta.AnalyzeTraffic(ctx, window)
	if err != nil {
		return nil, err
	}
	
	// Get historical metrics for comparison
	end := time.Now().Add(-window)
	start := end.Add(-window * 24) // Compare with last 24 periods
	
	historical, err := ta.storage.LoadTrafficMetrics(ctx, start, end)
	if err != nil || len(historical) == 0 {
		return []*TrafficMetrics{}, nil
	}
	
	// Calculate baseline metrics
	var totalRPS, totalBPS, totalErrorRate float64
	for _, metric := range historical {
		totalRPS += metric.RequestsPerSecond
		totalBPS += metric.BytesPerSecond
		totalErrorRate += metric.ErrorRate
	}
	
	avgRPS := totalRPS / float64(len(historical))
	avgBPS := totalBPS / float64(len(historical))
	avgErrorRate := totalErrorRate / float64(len(historical))
	
	// Check for anomalies (more than 3x normal)
	var anomalies []*TrafficMetrics
	
	if current.RequestsPerSecond > avgRPS*3 ||
		current.BytesPerSecond > avgBPS*3 ||
		current.ErrorRate > avgErrorRate*3 {
		anomalies = append(anomalies, current)
	}
	
	return anomalies, nil
}

// processMetrics runs in background to process and save metrics
func (ta *TrafficAnalyzerImpl) processMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		// Analyze traffic for different windows
		windows := []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
		}
		
		for _, window := range windows {
			metrics, err := ta.AnalyzeTraffic(ctx, window)
			if err != nil {
				ta.logger.Errorf("Failed to analyze traffic for window %v: %v", window, err)
				continue
			}
			
			// Save metrics to storage
			if err := ta.storage.SaveTrafficMetrics(ctx, metrics); err != nil {
				ta.logger.Errorf("Failed to save traffic metrics: %v", err)
			}
		}
		
		cancel()
	}
}

// getTopItems returns top items from a count map
func (ta *TrafficAnalyzerImpl) getTopItems(items map[string]int, limit int) []string {
	type item struct {
		key   string
		count int
	}
	
	var itemList []item
	for key, count := range items {
		itemList = append(itemList, item{key: key, count: count})
	}
	
	sort.Slice(itemList, func(i, j int) bool {
		return itemList[i].count > itemList[j].count
	})
	
	var topItems []string
	for i, item := range itemList {
		if i >= limit {
			break
		}
		topItems = append(topItems, item.key)
	}
	
	return topItems
}

// DetectSlowLoris detects Slowloris-style attacks
func (ta *TrafficAnalyzerImpl) DetectSlowLoris(ctx context.Context, ip net.IP, window time.Duration) (bool, float64, error) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	var slowRequests int
	var totalRequests int
	
	for _, req := range ta.requestBuffer {
		if req.SourceIP.Equal(ip) && req.Timestamp.After(cutoff) {
			totalRequests++
			
			// Check for slow request indicators
			if req.Method == "POST" && req.ContentLength == 0 {
				slowRequests++
			}
			
			// Check for incomplete headers
			if len(req.Headers) < 3 {
				slowRequests++
			}
		}
	}
	
	if totalRequests == 0 {
		return false, 0, nil
	}
	
	slowRatio := float64(slowRequests) / float64(totalRequests)
	
	// If more than 70% of requests are slow, it's likely Slowloris
	if slowRatio > 0.7 && totalRequests > 10 {
		return true, slowRatio, nil
	}
	
	return false, slowRatio, nil
}

// DetectHTTPFlood detects HTTP flood attacks
func (ta *TrafficAnalyzerImpl) DetectHTTPFlood(ctx context.Context, ip net.IP, window time.Duration) (bool, float64, error) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	var requestCount int
	
	for _, req := range ta.requestBuffer {
		if req.SourceIP.Equal(ip) && req.Timestamp.After(cutoff) {
			requestCount++
		}
	}
	
	requestsPerSecond := float64(requestCount) / window.Seconds()
	
	// If more than 50 requests per second from single IP, likely flood
	if requestsPerSecond > 50 {
		return true, requestsPerSecond / 50, nil
	}
	
	return false, requestsPerSecond / 50, nil
}

// DetectBotTraffic detects bot traffic patterns
func (ta *TrafficAnalyzerImpl) DetectBotTraffic(ctx context.Context, ip net.IP, window time.Duration) (bool, float64, error) {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	var botIndicators int
	var totalRequests int
	
	for _, req := range ta.requestBuffer {
		if req.SourceIP.Equal(ip) && req.Timestamp.After(cutoff) {
			totalRequests++
			
			// Check for bot indicators
			if ta.isBotUserAgent(req.UserAgent) {
				botIndicators++
			}
			
			// Check for suspicious patterns
			if req.Method == "GET" && len(req.Headers) < 5 {
				botIndicators++
			}
			
			// Check for rapid sequential requests
			// This would need more sophisticated timing analysis
		}
	}
	
	if totalRequests == 0 {
		return false, 0, nil
	}
	
	botRatio := float64(botIndicators) / float64(totalRequests)
	
	// If more than 80% of requests show bot indicators
	if botRatio > 0.8 && totalRequests > 5 {
		return true, botRatio, nil
	}
	
	return false, botRatio, nil
}

// isBotUserAgent checks if a user agent string indicates a bot
func (ta *TrafficAnalyzerImpl) isBotUserAgent(userAgent string) bool {
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python", "go-http-client",
		"automated", "script", "tool",
	}
	
	userAgentLower := strings.ToLower(userAgent)
	
	for _, pattern := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	
	return false
}

// processMetrics runs in background to process and aggregate metrics
func (ta *TrafficAnalyzerImpl) processMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		// Analyze different time windows
		windows := []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
		}
		
		for _, window := range windows {
			metrics, err := ta.AnalyzeTraffic(ctx, window)
			if err != nil {
				ta.logger.Errorf("Failed to analyze traffic: %v", err)
				continue
			}
			
			// Save to storage
			if err := ta.storage.SaveTrafficMetrics(ctx, metrics); err != nil {
				ta.logger.Errorf("Failed to save traffic metrics: %v", err)
			}
		}
		
		cancel()
	}
}

// GetRequestsInWindow returns requests within a time window
func (ta *TrafficAnalyzerImpl) GetRequestsInWindow(window time.Duration) []*RequestContext {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	var requests []*RequestContext
	for _, req := range ta.requestBuffer {
		if req.Timestamp.After(cutoff) {
			requests = append(requests, req)
		}
	}
	
	return requests
}

// GetIPRequestCount returns request count for a specific IP in a time window
func (ta *TrafficAnalyzerImpl) GetIPRequestCount(ip net.IP, window time.Duration) int {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	count := 0
	for _, req := range ta.requestBuffer {
		if req.SourceIP.Equal(ip) && req.Timestamp.After(cutoff) {
			count++
		}
	}
	
	return count
}

// GetUniqueIPsInWindow returns unique IPs in a time window
func (ta *TrafficAnalyzerImpl) GetUniqueIPsInWindow(window time.Duration) []net.IP {
	ta.bufferMu.RLock()
	defer ta.bufferMu.RUnlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	uniqueIPs := make(map[string]net.IP)
	
	for _, req := range ta.requestBuffer {
		if req.Timestamp.After(cutoff) {
			uniqueIPs[req.SourceIP.String()] = req.SourceIP
		}
	}
	
	var ips []net.IP
	for _, ip := range uniqueIPs {
		ips = append(ips, ip)
	}
	
	return ips
}

// CalculateEntropy calculates entropy of request patterns (for randomness detection)
func (ta *TrafficAnalyzerImpl) CalculateEntropy(requests []*RequestContext) float64 {
	if len(requests) == 0 {
		return 0
	}
	
	// Calculate entropy based on path distribution
	pathCounts := make(map[string]int)
	for _, req := range requests {
		pathCounts[req.Path]++
	}
	
	total := float64(len(requests))
	entropy := 0.0
	
	for _, count := range pathCounts {
		probability := float64(count) / total
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}
	
	return entropy
}