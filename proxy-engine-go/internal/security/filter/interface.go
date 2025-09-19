package filter

import (
	"context"
)

// ContentFilter defines the interface for content filtering
type ContentFilter interface {
	// Filter checks if the content request should be allowed
	Filter(ctx context.Context, request *ContentRequest) (*FilterResult, error)
	
	// AddRule adds a new filtering rule
	AddRule(ctx context.Context, rule *FilterRule) error
	
	// RemoveRule removes a filtering rule by ID
	RemoveRule(ctx context.Context, ruleID string) error
	
	// UpdateRule updates an existing filtering rule
	UpdateRule(ctx context.Context, rule *FilterRule) error
	
	// GetRules returns all filtering rules
	GetRules(ctx context.Context) ([]*FilterRule, error)
	
	// GetRulesByType returns rules of a specific type
	GetRulesByType(ctx context.Context, ruleType RuleType) ([]*FilterRule, error)
	
	// GetStats returns filtering statistics
	GetStats(ctx context.Context) (*FilterStats, error)
	
	// ReloadRules reloads rules from storage
	ReloadRules(ctx context.Context) error
}

// RuleStorage defines the interface for rule persistence
type RuleStorage interface {
	// SaveRule saves a rule to storage
	SaveRule(ctx context.Context, rule *FilterRule) error
	
	// LoadRules loads all rules from storage
	LoadRules(ctx context.Context) ([]*FilterRule, error)
	
	// DeleteRule deletes a rule from storage
	DeleteRule(ctx context.Context, ruleID string) error
	
	// UpdateRule updates a rule in storage
	UpdateRule(ctx context.Context, rule *FilterRule) error
}

// RuleMatcher defines the interface for rule matching
type RuleMatcher interface {
	// Match checks if a request matches the rule
	Match(request *ContentRequest, rule *FilterRule) bool
	
	// GetMatcherType returns the type of matcher
	GetMatcherType() RuleType
}