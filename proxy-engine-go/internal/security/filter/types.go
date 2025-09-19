package filter

import (
	"time"
)

// FilterAction defines what action to take when content matches a rule
type FilterAction int

const (
	ActionAllow FilterAction = iota
	ActionBlock
	ActionLog
	ActionQuarantine
)

// FilterRule represents a content filtering rule
type FilterRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Pattern     string        `json:"pattern"`
	Type        RuleType      `json:"type"`
	Action      FilterAction  `json:"action"`
	Priority    int           `json:"priority"`
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Description string        `json:"description"`
}

// RuleType defines the type of filtering rule
type RuleType int

const (
	RuleTypeURL RuleType = iota
	RuleTypeDomain
	RuleTypeKeyword
	RuleTypeRegex
	RuleTypeContentType
	RuleTypeFileExtension
)

// FilterResult contains the result of content filtering
type FilterResult struct {
	Allowed     bool          `json:"allowed"`
	Action      FilterAction  `json:"action"`
	MatchedRule *FilterRule   `json:"matched_rule,omitempty"`
	Reason      string        `json:"reason"`
	Timestamp   time.Time     `json:"timestamp"`
}

// ContentRequest represents a request to be filtered
type ContentRequest struct {
	URL         string            `json:"url"`
	Domain      string            `json:"domain"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	UserID      string            `json:"user_id"`
	OrgID       string            `json:"org_id"`
	Body        []byte            `json:"body,omitempty"`
}

// FilterStats contains filtering statistics
type FilterStats struct {
	TotalRequests   int64 `json:"total_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	AllowedRequests int64 `json:"allowed_requests"`
	LoggedRequests  int64 `json:"logged_requests"`
}