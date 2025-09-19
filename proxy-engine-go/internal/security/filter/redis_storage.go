package filter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v9"
)

const (
	rulesKeyPrefix = "content_filter:rules:"
	rulesListKey   = "content_filter:rules_list"
)

// RedisStorage implements RuleStorage using Redis
type RedisStorage struct {
	client *redis.Client
}

// NewRedisStorage creates a new Redis-based rule storage
func NewRedisStorage(client *redis.Client) *RedisStorage {
	return &RedisStorage{
		client: client,
	}
}

// SaveRule saves a rule to Redis
func (s *RedisStorage) SaveRule(ctx context.Context, rule *FilterRule) error {
	// Serialize rule to JSON
	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}
	
	// Save rule data
	ruleKey := rulesKeyPrefix + rule.ID
	if err := s.client.Set(ctx, ruleKey, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to save rule to Redis: %w", err)
	}
	
	// Add rule ID to the list of rules
	if err := s.client.SAdd(ctx, rulesListKey, rule.ID).Err(); err != nil {
		return fmt.Errorf("failed to add rule ID to list: %w", err)
	}
	
	return nil
}

// LoadRules loads all rules from Redis
func (s *RedisStorage) LoadRules(ctx context.Context) ([]*FilterRule, error) {
	// Get all rule IDs
	ruleIDs, err := s.client.SMembers(ctx, rulesListKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get rule IDs: %w", err)
	}
	
	var rules []*FilterRule
	
	// Load each rule
	for _, ruleID := range ruleIDs {
		ruleKey := rulesKeyPrefix + ruleID
		data, err := s.client.Get(ctx, ruleKey).Result()
		if err != nil {
			if err == redis.Nil {
				// Rule doesn't exist, remove from list
				s.client.SRem(ctx, rulesListKey, ruleID)
				continue
			}
			return nil, fmt.Errorf("failed to get rule %s: %w", ruleID, err)
		}
		
		var rule FilterRule
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule %s: %w", ruleID, err)
		}
		
		rules = append(rules, &rule)
	}
	
	return rules, nil
}

// DeleteRule deletes a rule from Redis
func (s *RedisStorage) DeleteRule(ctx context.Context, ruleID string) error {
	ruleKey := rulesKeyPrefix + ruleID
	
	// Delete rule data
	if err := s.client.Del(ctx, ruleKey).Err(); err != nil {
		return fmt.Errorf("failed to delete rule from Redis: %w", err)
	}
	
	// Remove rule ID from the list
	if err := s.client.SRem(ctx, rulesListKey, ruleID).Err(); err != nil {
		return fmt.Errorf("failed to remove rule ID from list: %w", err)
	}
	
	return nil
}

// UpdateRule updates a rule in Redis
func (s *RedisStorage) UpdateRule(ctx context.Context, rule *FilterRule) error {
	// Check if rule exists
	ruleKey := rulesKeyPrefix + rule.ID
	exists, err := s.client.Exists(ctx, ruleKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check if rule exists: %w", err)
	}
	
	if exists == 0 {
		return fmt.Errorf("rule not found: %s", rule.ID)
	}
	
	// Update rule (same as save)
	return s.SaveRule(ctx, rule)
}

// GetRuleByID gets a specific rule by ID
func (s *RedisStorage) GetRuleByID(ctx context.Context, ruleID string) (*FilterRule, error) {
	ruleKey := rulesKeyPrefix + ruleID
	data, err := s.client.Get(ctx, ruleKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("rule not found: %s", ruleID)
		}
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}
	
	var rule FilterRule
	if err := json.Unmarshal([]byte(data), &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
	}
	
	return &rule, nil
}

// ClearAllRules removes all rules from Redis
func (s *RedisStorage) ClearAllRules(ctx context.Context) error {
	// Get all rule IDs
	ruleIDs, err := s.client.SMembers(ctx, rulesListKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get rule IDs: %w", err)
	}
	
	// Delete all rule data
	for _, ruleID := range ruleIDs {
		ruleKey := rulesKeyPrefix + ruleID
		if err := s.client.Del(ctx, ruleKey).Err(); err != nil {
			return fmt.Errorf("failed to delete rule %s: %w", ruleID, err)
		}
	}
	
	// Clear the rules list
	if err := s.client.Del(ctx, rulesListKey).Err(); err != nil {
		return fmt.Errorf("failed to clear rules list: %w", err)
	}
	
	return nil
}