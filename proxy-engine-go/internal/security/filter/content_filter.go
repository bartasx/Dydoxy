package filter

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Engine implements the ContentFilter interface
type Engine struct {
	storage     RuleStorage
	listManager ListManager
	matchers    map[RuleType]RuleMatcher
	rules       []*FilterRule
	stats       *FilterStats
	logger      *logrus.Logger
	mu          sync.RWMutex
}

// NewEngine creates a new content filtering engine
func NewEngine(storage RuleStorage, logger *logrus.Logger) *Engine {
	engine := &Engine{
		storage:  storage,
		matchers: make(map[RuleType]RuleMatcher),
		rules:    make([]*FilterRule, 0),
		stats:    &FilterStats{},
		logger:   logger,
	}
	
	// Register default matchers
	engine.registerMatchers()
	
	return engine
}

// NewEngineWithLists creates a new content filtering engine with list manager
func NewEngineWithLists(storage RuleStorage, listManager ListManager, logger *logrus.Logger) *Engine {
	engine := &Engine{
		storage:     storage,
		listManager: listManager,
		matchers:    make(map[RuleType]RuleMatcher),
		rules:       make([]*FilterRule, 0),
		stats:       &FilterStats{},
		logger:      logger,
	}
	
	// Register default matchers
	engine.registerMatchers()
	
	return engine
}

// registerMatchers registers all available rule matchers
func (e *Engine) registerMatchers() {
	e.matchers[RuleTypeURL] = NewURLMatcher()
	e.matchers[RuleTypeDomain] = NewDomainMatcher()
	e.matchers[RuleTypeKeyword] = NewKeywordMatcher()
	e.matchers[RuleTypeRegex] = NewRegexMatcher()
	e.matchers[RuleTypeContentType] = NewContentTypeMatcher()
	e.matchers[RuleTypeFileExtension] = NewFileExtensionMatcher()
}

// Filter checks if the content request should be allowed
func (e *Engine) Filter(ctx context.Context, request *ContentRequest) (*FilterResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	e.stats.TotalRequests++
	
	// First check blacklist/whitelist if list manager is available
	if e.listManager != nil {
		if listResult, err := e.checkLists(ctx, request); err == nil && listResult.Found {
			result := &FilterResult{
				Timestamp: time.Now(),
			}
			
			if listResult.ListType == ListTypeBlacklist {
				result.Allowed = false
				result.Action = ActionBlock
				result.Reason = fmt.Sprintf("Blocked by blacklist: %s", listResult.Reason)
				e.stats.BlockedRequests++
			} else {
				result.Allowed = true
				result.Action = ActionAllow
				result.Reason = fmt.Sprintf("Allowed by whitelist: %s", listResult.Reason)
				e.stats.AllowedRequests++
			}
			
			return result, nil
		}
	}
	
	// Sort rules by priority (higher priority first)
	sortedRules := make([]*FilterRule, len(e.rules))
	copy(sortedRules, e.rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority > sortedRules[j].Priority
	})
	
	// Check each rule
	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}
		
		matcher, exists := e.matchers[rule.Type]
		if !exists {
			e.logger.Warnf("No matcher found for rule type: %v", rule.Type)
			continue
		}
		
		if matcher.Match(request, rule) {
			result := &FilterResult{
				Action:      rule.Action,
				MatchedRule: rule,
				Reason:      fmt.Sprintf("Matched rule: %s", rule.Name),
				Timestamp:   time.Now(),
			}
			
			switch rule.Action {
			case ActionAllow:
				result.Allowed = true
				e.stats.AllowedRequests++
			case ActionBlock:
				result.Allowed = false
				e.stats.BlockedRequests++
			case ActionLog:
				result.Allowed = true
				e.stats.LoggedRequests++
				e.logger.Infof("Content logged - Rule: %s, URL: %s, User: %s", 
					rule.Name, request.URL, request.UserID)
			case ActionQuarantine:
				result.Allowed = false
				e.stats.BlockedRequests++
				e.logger.Warnf("Content quarantined - Rule: %s, URL: %s, User: %s", 
					rule.Name, request.URL, request.UserID)
			}
			
			return result, nil
		}
	}
	
	// Default action: allow if no rules match
	e.stats.AllowedRequests++
	return &FilterResult{
		Allowed:   true,
		Action:    ActionAllow,
		Reason:    "No matching rules",
		Timestamp: time.Now(),
	}, nil
}

// checkLists checks if the request matches any blacklist or whitelist entries
func (e *Engine) checkLists(ctx context.Context, request *ContentRequest) (*ListCheckResult, error) {
	// Check domain
	if request.Domain != "" {
		if result, err := e.listManager.CheckValue(ctx, request.Domain); err == nil {
			return result, nil
		}
	}
	
	// Check URL
	if request.URL != "" {
		if result, err := e.listManager.CheckValue(ctx, request.URL); err == nil {
			return result, nil
		}
	}
	
	return &ListCheckResult{Found: false}, nil
}

// AddRule adds a new filtering rule
func (e *Engine) AddRule(ctx context.Context, rule *FilterRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	
	// Validate rule
	if err := e.validateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}
	
	// Save to storage
	if err := e.storage.SaveRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to save rule: %w", err)
	}
	
	// Add to memory
	e.mu.Lock()
	defer e.mu.Unlock()
	
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	e.rules = append(e.rules, rule)
	
	e.logger.Infof("Added filtering rule: %s (ID: %s)", rule.Name, rule.ID)
	return nil
}

// RemoveRule removes a filtering rule by ID
func (e *Engine) RemoveRule(ctx context.Context, ruleID string) error {
	// Remove from storage
	if err := e.storage.DeleteRule(ctx, ruleID); err != nil {
		return fmt.Errorf("failed to delete rule from storage: %w", err)
	}
	
	// Remove from memory
	e.mu.Lock()
	defer e.mu.Unlock()
	
	for i, rule := range e.rules {
		if rule.ID == ruleID {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			e.logger.Infof("Removed filtering rule: %s (ID: %s)", rule.Name, rule.ID)
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", ruleID)
}

// UpdateRule updates an existing filtering rule
func (e *Engine) UpdateRule(ctx context.Context, rule *FilterRule) error {
	if err := e.validateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}
	
	// Update in storage
	if err := e.storage.UpdateRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to update rule in storage: %w", err)
	}
	
	// Update in memory
	e.mu.Lock()
	defer e.mu.Unlock()
	
	for i, existingRule := range e.rules {
		if existingRule.ID == rule.ID {
			rule.UpdatedAt = time.Now()
			e.rules[i] = rule
			e.logger.Infof("Updated filtering rule: %s (ID: %s)", rule.Name, rule.ID)
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", rule.ID)
}

// GetRules returns all filtering rules
func (e *Engine) GetRules(ctx context.Context) ([]*FilterRule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	rules := make([]*FilterRule, len(e.rules))
	copy(rules, e.rules)
	return rules, nil
}

// GetRulesByType returns rules of a specific type
func (e *Engine) GetRulesByType(ctx context.Context, ruleType RuleType) ([]*FilterRule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var filteredRules []*FilterRule
	for _, rule := range e.rules {
		if rule.Type == ruleType {
			filteredRules = append(filteredRules, rule)
		}
	}
	
	return filteredRules, nil
}

// GetStats returns filtering statistics
func (e *Engine) GetStats(ctx context.Context) (*FilterStats, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Return a copy of stats
	return &FilterStats{
		TotalRequests:   e.stats.TotalRequests,
		BlockedRequests: e.stats.BlockedRequests,
		AllowedRequests: e.stats.AllowedRequests,
		LoggedRequests:  e.stats.LoggedRequests,
	}, nil
}

// ReloadRules reloads rules from storage
func (e *Engine) ReloadRules(ctx context.Context) error {
	rules, err := e.storage.LoadRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to load rules from storage: %w", err)
	}
	
	e.mu.Lock()
	defer e.mu.Unlock()
	
	e.rules = rules
	e.logger.Infof("Reloaded %d filtering rules", len(rules))
	return nil
}

// validateRule validates a filtering rule
func (e *Engine) validateRule(rule *FilterRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	
	if rule.Pattern == "" {
		return fmt.Errorf("rule pattern cannot be empty")
	}
	
	if rule.Priority < 0 {
		return fmt.Errorf("rule priority cannot be negative")
	}
	
	// Validate that we have a matcher for this rule type
	if _, exists := e.matchers[rule.Type]; !exists {
		return fmt.Errorf("unsupported rule type: %v", rule.Type)
	}
	
	return nil
}