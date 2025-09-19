package ddos

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Protector implements the DDoSProtector interface
type Protector struct {
	config            *DDoSConfig
	storage           DDoSStorage
	detector          AttackDetector
	mitigationEngine  MitigationEngine
	trafficAnalyzer   TrafficAnalyzer
	reputationService ReputationService
	geoFilter         GeoFilter
	alertManager      AlertManager
	behavioralAnalyzer BehavioralAnalyzer
	mlDetector        MLDetector
	logger            *logrus.Logger
	mu                sync.RWMutex
	stats             *DDoSStats
	lastStatsUpdate   time.Time
}

// NewProtector creates a new DDoS protector
func NewProtector(
	storage DDoSStorage,
	detector AttackDetector,
	mitigationEngine MitigationEngine,
	trafficAnalyzer TrafficAnalyzer,
	reputationService ReputationService,
	geoFilter GeoFilter,
	alertManager AlertManager,
	logger *logrus.Logger,
) *Protector {
	protector := &Protector{
		storage:           storage,
		detector:          detector,
		mitigationEngine:  mitigationEngine,
		trafficAnalyzer:   trafficAnalyzer,
		reputationService: reputationService,
		geoFilter:         geoFilter,
		alertManager:      alertManager,
		logger:            logger,
		stats:             &DDoSStats{},
		lastStatsUpdate:   time.Now(),
	}
	
	// Load configuration
	if config, err := storage.LoadConfig(context.Background()); err == nil {
		protector.config = config
	} else {
		// Use default configuration
		protector.config = protector.getDefaultConfig()
	}
	
	// Load statistics
	if stats, err := storage.GetStats(context.Background()); err == nil {
		protector.stats = stats
	}
	
	return protector
}

// AnalyzeRequest analyzes a request for potential DDoS patterns
func (p *Protector) AnalyzeRequest(ctx context.Context, request *RequestContext) (*DetectionResult, error) {
	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()
	
	// Record the request for traffic analysis
	if err := p.trafficAnalyzer.RecordRequest(ctx, request); err != nil {
		p.logger.Warnf("Failed to record request for analysis: %v", err)
	}
	
	// Update statistics
	p.updateStats(func(stats *DDoSStats) {
		stats.TotalRequests++
	})
	
	// Check IP reputation first
	if config.ReputationEnabled {
		if reputation, err := p.reputationService.GetReputation(ctx, request.SourceIP); err == nil {
			if reputation.Score < config.ReputationThreshold {
				return &DetectionResult{
					IsAttack:    true,
					AttackType:  AttackTypeDistributed,
					ThreatLevel: ThreatLevelHigh,
					Confidence:  0.9,
					Reason:      fmt.Sprintf("Low reputation score: %.2f", reputation.Score),
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}
	
	// Check geographic filtering
	if config.GeoFilteringEnabled {
		if country, err := p.geoFilter.GetCountry(ctx, request.SourceIP); err == nil {
			request.Country = country
			
			if blocked, err := p.geoFilter.IsBlocked(ctx, country); err == nil && blocked {
				return &DetectionResult{
					IsAttack:    true,
					AttackType:  AttackTypeDistributed,
					ThreatLevel: ThreatLevelMedium,
					Confidence:  0.8,
					Reason:      fmt.Sprintf("Request from blocked country: %s", country),
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}
	
	// Get current traffic metrics
	metrics, err := p.trafficAnalyzer.AnalyzeTraffic(ctx, config.ShortTermWindow)
	if err != nil {
		p.logger.Warnf("Failed to analyze traffic: %v", err)
		metrics = &TrafficMetrics{Timestamp: time.Now()}
	}
	
	// Check for volumetric attacks
	if metrics.RequestsPerSecond > config.RequestsPerSecondThreshold {
		return &DetectionResult{
			IsAttack:    true,
			AttackType:  AttackTypeVolumetric,
			ThreatLevel: p.calculateThreatLevel(metrics.RequestsPerSecond, config.RequestsPerSecondThreshold),
			Confidence:  0.85,
			Metrics:     metrics,
			Reason:      fmt.Sprintf("High request rate: %.2f req/s", metrics.RequestsPerSecond),
			Timestamp:   time.Now(),
		}, nil
	}
	
	// Check for connection flooding
	if metrics.ConnectionsPerSecond > config.ConnectionsPerSecondThreshold {
		return &DetectionResult{
			IsAttack:    true,
			AttackType:  AttackTypeProtocol,
			ThreatLevel: p.calculateThreatLevel(metrics.ConnectionsPerSecond, config.ConnectionsPerSecondThreshold),
			Confidence:  0.8,
			Metrics:     metrics,
			Reason:      fmt.Sprintf("High connection rate: %.2f conn/s", metrics.ConnectionsPerSecond),
			Timestamp:   time.Now(),
		}, nil
	}
	
	// Check error rate for potential application attacks
	if metrics.ErrorRate > config.ErrorRateThreshold {
		return &DetectionResult{
			IsAttack:    true,
			AttackType:  AttackTypeApplication,
			ThreatLevel: ThreatLevelMedium,
			Confidence:  0.7,
			Metrics:     metrics,
			Reason:      fmt.Sprintf("High error rate: %.2f%%", metrics.ErrorRate*100),
			Timestamp:   time.Now(),
		}, nil
	}
	
	// Use ML detector if available and enabled
	if p.mlDetector != nil && config.MachineLearning {
		if features, err := p.mlDetector.ExtractFeatures(ctx, request, metrics); err == nil {
			if isAttack, confidence, err := p.mlDetector.Predict(ctx, features); err == nil && isAttack {
				return &DetectionResult{
					IsAttack:    true,
					AttackType:  AttackTypeApplication,
					ThreatLevel: p.confidenceToThreatLevel(confidence),
					Confidence:  confidence,
					Metrics:     metrics,
					Reason:      fmt.Sprintf("ML detection (confidence: %.2f)", confidence),
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}
	
	// Use behavioral analysis if available and enabled
	if p.behavioralAnalyzer != nil && config.BehavioralAnalysis {
		if anomaly, confidence, err := p.behavioralAnalyzer.DetectAnomalies(ctx, request.SourceIP, request); err == nil && anomaly {
			return &DetectionResult{
				IsAttack:    true,
				AttackType:  AttackTypeSlow,
				ThreatLevel: p.confidenceToThreatLevel(confidence),
				Confidence:  confidence,
				Metrics:     metrics,
				Reason:      fmt.Sprintf("Behavioral anomaly (confidence: %.2f)", confidence),
				Timestamp:   time.Now(),
			}, nil
		}
	}
	
	// Use pattern-based detection
	if detectionResult, err := p.detector.DetectAttack(ctx, metrics, request); err == nil && detectionResult.IsAttack {
		return detectionResult, nil
	}
	
	// No attack detected
	return &DetectionResult{
		IsAttack:    false,
		ThreatLevel: ThreatLevelLow,
		Confidence:  0.1,
		Metrics:     metrics,
		Reason:      "No attack patterns detected",
		Timestamp:   time.Now(),
	}, nil
}

// ApplyMitigation applies mitigation measures for detected attacks
func (p *Protector) ApplyMitigation(ctx context.Context, result *DetectionResult, request *RequestContext) (*MitigationResult, error) {
	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()
	
	if !config.AutoMitigationEnabled {
		return &MitigationResult{
			Action:    "none",
			Applied:   false,
			Reason:    "Auto-mitigation disabled",
			Timestamp: time.Now(),
		}, nil
	}
	
	// Create attack event
	event := &AttackEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		SourceIP:    request.SourceIP,
		Type:        result.AttackType,
		Level:       result.ThreatLevel,
		Metrics:     map[string]interface{}{
			"confidence": result.Confidence,
			"reason":     result.Reason,
		},
		UserAgent:   request.UserAgent,
		RequestPath: request.Path,
		Method:      request.Method,
		Headers:     request.Headers,
		Blocked:     false,
		Action:      "pending",
		Reason:      result.Reason,
	}
	
	// Save attack event
	if err := p.storage.SaveAttackEvent(ctx, event); err != nil {
		p.logger.Errorf("Failed to save attack event: %v", err)
	}
	
	// Update statistics
	p.updateStats(func(stats *DDoSStats) {
		stats.AttacksDetected++
		if stats.AttacksByType == nil {
			stats.AttacksByType = make(map[AttackType]int64)
		}
		if stats.AttacksByLevel == nil {
			stats.AttacksByLevel = make(map[ThreatLevel]int64)
		}
		stats.AttacksByType[result.AttackType]++
		stats.AttacksByLevel[result.ThreatLevel]++
		now := time.Now()
		stats.LastAttack = &now
	})
	
	// Determine mitigation action based on threat level and attack type
	var action *MitigationAction
	var mitigationResult *MitigationResult
	
	switch result.ThreatLevel {
	case ThreatLevelCritical:
		// Block IP immediately
		action = &MitigationAction{
			ID:        uuid.New().String(),
			Type:      "block",
			Target:    request.SourceIP.String(),
			Duration:  config.BlockDuration * 2, // Extended block for critical threats
			Reason:    fmt.Sprintf("Critical threat detected: %s", result.Reason),
			Severity:  result.ThreatLevel,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(config.BlockDuration * 2),
			Active:    true,
		}
		
		mitigationResult = &MitigationResult{
			Action:    "block",
			Applied:   true,
			Duration:  config.BlockDuration * 2,
			Reason:    "Critical threat - IP blocked",
			Timestamp: time.Now(),
		}
		
	case ThreatLevelHigh:
		// Block IP
		action = &MitigationAction{
			ID:        uuid.New().String(),
			Type:      "block",
			Target:    request.SourceIP.String(),
			Duration:  config.BlockDuration,
			Reason:    fmt.Sprintf("High threat detected: %s", result.Reason),
			Severity:  result.ThreatLevel,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(config.BlockDuration),
			Active:    true,
		}
		
		mitigationResult = &MitigationResult{
			Action:    "block",
			Applied:   true,
			Duration:  config.BlockDuration,
			Reason:    "High threat - IP blocked",
			Timestamp: time.Now(),
		}
		
	case ThreatLevelMedium:
		// Apply rate limiting or challenge
		if result.AttackType == AttackTypeVolumetric || result.AttackType == AttackTypeProtocol {
			action = &MitigationAction{
				ID:        uuid.New().String(),
				Type:      "rate_limit",
				Target:    request.SourceIP.String(),
				Duration:  config.ChallengeDuration,
				Reason:    fmt.Sprintf("Medium threat detected: %s", result.Reason),
				Severity:  result.ThreatLevel,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(config.ChallengeDuration),
				Active:    true,
				Metadata: map[string]interface{}{
					"rate_limit": config.PerIPRateLimit / 2, // Reduced rate limit
				},
			}
			
			mitigationResult = &MitigationResult{
				Action:    "rate_limit",
				Applied:   true,
				Duration:  config.ChallengeDuration,
				Reason:    "Medium threat - rate limited",
				Metadata:  map[string]interface{}{"rate_limit": config.PerIPRateLimit / 2},
				Timestamp: time.Now(),
			}
		} else {
			action = &MitigationAction{
				ID:        uuid.New().String(),
				Type:      "challenge",
				Target:    request.SourceIP.String(),
				Duration:  config.ChallengeDuration,
				Reason:    fmt.Sprintf("Medium threat detected: %s", result.Reason),
				Severity:  result.ThreatLevel,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(config.ChallengeDuration),
				Active:    true,
			}
			
			mitigationResult = &MitigationResult{
				Action:    "challenge",
				Applied:   true,
				Duration:  config.ChallengeDuration,
				Reason:    "Medium threat - challenge required",
				Timestamp: time.Now(),
			}
		}
		
	default:
		// Low threat - just log
		mitigationResult = &MitigationResult{
			Action:    "log",
			Applied:   true,
			Reason:    "Low threat - logged for monitoring",
			Timestamp: time.Now(),
		}
	}
	
	// Apply mitigation action
	if action != nil {
		if err := p.mitigationEngine.CreateMitigation(ctx, action); err != nil {
			p.logger.Errorf("Failed to create mitigation action: %v", err)
			mitigationResult.Applied = false
			mitigationResult.Reason = fmt.Sprintf("Failed to apply mitigation: %v", err)
		} else {
			// Update attack event
			event.Blocked = (action.Type == "block")
			event.Action = action.Type
			p.storage.SaveAttackEvent(ctx, event)
			
			// Update statistics
			p.updateStats(func(stats *DDoSStats) {
				if action.Type == "block" {
					stats.BlockedRequests++
				} else if action.Type == "challenge" {
					stats.ChallengedRequests++
				}
				stats.MitigationActions++
				stats.ActiveMitigations++
			})
		}
	}
	
	// Create alert if threshold is met
	if result.ThreatLevel >= config.AlertThreshold && config.AlertingEnabled {
		alert := &DDoSAlert{
			ID:          uuid.New().String(),
			Level:       p.threatLevelToAlertLevel(result.ThreatLevel),
			Title:       fmt.Sprintf("%s Attack Detected", result.AttackType),
			Message:     fmt.Sprintf("Attack from %s: %s", request.SourceIP.String(), result.Reason),
			AttackType:  result.AttackType,
			ThreatLevel: result.ThreatLevel,
			SourceIPs:   []string{request.SourceIP.String()},
			Metrics:     result.Metrics,
			Actions:     []string{mitigationResult.Action},
			Timestamp:   time.Now(),
			Resolved:    false,
		}
		
		if err := p.alertManager.CreateAlert(ctx, alert); err != nil {
			p.logger.Errorf("Failed to create alert: %v", err)
		}
	}
	
	return mitigationResult, nil
}

// UpdateConfig updates the DDoS protection configuration
func (p *Protector) UpdateConfig(ctx context.Context, config *DDoSConfig) error {
	p.mu.Lock()
	p.config = config
	p.mu.Unlock()
	
	if err := p.storage.SaveConfig(ctx, config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	
	p.logger.Infof("DDoS protection configuration updated")
	return nil
}

// GetConfig returns the current configuration
func (p *Protector) GetConfig(ctx context.Context) (*DDoSConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Return a copy to prevent external modifications
	configCopy := *p.config
	return &configCopy, nil
}

// GetStats returns current DDoS protection statistics
func (p *Protector) GetStats(ctx context.Context) (*DDoSStats, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Update current threat level based on recent activity
	p.stats.CurrentThreatLevel = p.calculateCurrentThreatLevel(ctx)
	p.stats.LastUpdated = time.Now()
	
	// Return a copy
	statsCopy := *p.stats
	return &statsCopy, nil
}

// GetActiveAttacks returns currently active attacks
func (p *Protector) GetActiveAttacks(ctx context.Context) ([]*AttackEvent, error) {
	// Get recent attack events (last 15 minutes)
	end := time.Now()
	start := end.Add(-15 * time.Minute)
	
	return p.storage.ListAttackEvents(ctx, start, end, 100)
}

// GetActiveMitigations returns currently active mitigations
func (p *Protector) GetActiveMitigations(ctx context.Context) ([]*MitigationAction, error) {
	return p.mitigationEngine.ListMitigations(ctx)
}

// ResetStats resets statistics counters
func (p *Protector) ResetStats(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.stats = &DDoSStats{
		AttacksByType:  make(map[AttackType]int64),
		AttacksByLevel: make(map[ThreatLevel]int64),
		LastUpdated:    time.Now(),
	}
	
	return p.storage.UpdateStats(ctx, p.stats)
}

// Helper methods

func (p *Protector) getDefaultConfig() *DDoSConfig {
	return &DDoSConfig{
		RequestsPerSecondThreshold:    100,
		ConnectionsPerSecondThreshold: 50,
		ErrorRateThreshold:            0.1, // 10%
		ShortTermWindow:               1 * time.Minute,
		MediumTermWindow:              5 * time.Minute,
		LongTermWindow:                15 * time.Minute,
		AutoMitigationEnabled:         true,
		BlockDuration:                 10 * time.Minute,
		ChallengeDuration:             5 * time.Minute,
		ReputationEnabled:             true,
		ReputationThreshold:           30.0,
		GeoFilteringEnabled:           false,
		GlobalRateLimit:               1000,
		PerIPRateLimit:                10,
		BehavioralAnalysis:            true,
		MachineLearning:               false,
		LogLevel:                      "info",
		AlertingEnabled:               true,
		AlertThreshold:                ThreatLevelMedium,
	}
}

func (p *Protector) calculateThreatLevel(current, threshold float64) ThreatLevel {
	ratio := current / threshold
	
	if ratio >= 5.0 {
		return ThreatLevelCritical
	} else if ratio >= 2.0 {
		return ThreatLevelHigh
	} else if ratio >= 1.5 {
		return ThreatLevelMedium
	}
	
	return ThreatLevelLow
}

func (p *Protector) confidenceToThreatLevel(confidence float64) ThreatLevel {
	if confidence >= 0.9 {
		return ThreatLevelCritical
	} else if confidence >= 0.7 {
		return ThreatLevelHigh
	} else if confidence >= 0.5 {
		return ThreatLevelMedium
	}
	
	return ThreatLevelLow
}

func (p *Protector) threatLevelToAlertLevel(level ThreatLevel) AlertLevel {
	switch level {
	case ThreatLevelCritical:
		return AlertLevelCritical
	case ThreatLevelHigh:
		return AlertLevelError
	case ThreatLevelMedium:
		return AlertLevelWarning
	default:
		return AlertLevelInfo
	}
}

func (p *Protector) calculateCurrentThreatLevel(ctx context.Context) ThreatLevel {
	// Get recent attacks to determine current threat level
	attacks, err := p.GetActiveAttacks(ctx)
	if err != nil || len(attacks) == 0 {
		return ThreatLevelLow
	}
	
	// Find the highest threat level in recent attacks
	maxLevel := ThreatLevelLow
	for _, attack := range attacks {
		if attack.Level > maxLevel {
			maxLevel = attack.Level
		}
	}
	
	return maxLevel
}

func (p *Protector) updateStats(updateFunc func(*DDoSStats)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	updateFunc(p.stats)
	
	// Periodically save stats to storage
	if time.Since(p.lastStatsUpdate) > 1*time.Minute {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			if err := p.storage.UpdateStats(ctx, p.stats); err != nil {
				p.logger.Errorf("Failed to update stats in storage: %v", err)
			}
		}()
		p.lastStatsUpdate = time.Now()
	}
}