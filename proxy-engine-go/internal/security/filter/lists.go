package filter

import (
	"time"
)

// ListType defines the type of list (blacklist or whitelist)
type ListType int

const (
	ListTypeBlacklist ListType = iota
	ListTypeWhitelist
)

// ListEntry represents an entry in a blacklist or whitelist
type ListEntry struct {
	ID          string    `json:"id"`
	Value       string    `json:"value"`
	Type        ListType  `json:"type"`
	Category    string    `json:"category"`
	Source      string    `json:"source"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Enabled     bool      `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ListCategory defines common categories for list entries
type ListCategory string

const (
	CategoryMalware     ListCategory = "malware"
	CategoryPhishing    ListCategory = "phishing"
	CategoryAdult       ListCategory = "adult"
	CategoryGambling    ListCategory = "gambling"
	CategorySocialMedia ListCategory = "social_media"
	CategoryStreaming   ListCategory = "streaming"
	CategoryNews        ListCategory = "news"
	CategoryShopping    ListCategory = "shopping"
	CategoryEducation   ListCategory = "education"
	CategoryBusiness    ListCategory = "business"
	CategoryCustom      ListCategory = "custom"
)

// ListSource defines the source of list entries
type ListSource string

const (
	SourceManual      ListSource = "manual"
	SourceThreatFeed  ListSource = "threat_feed"
	SourceAI          ListSource = "ai_detection"
	SourceCommunity   ListSource = "community"
	SourceCommercial  ListSource = "commercial"
)

// ListStats contains statistics for blacklists and whitelists
type ListStats struct {
	BlacklistEntries int64            `json:"blacklist_entries"`
	WhitelistEntries int64            `json:"whitelist_entries"`
	CategoriesCount  map[string]int64 `json:"categories_count"`
	SourcesCount     map[string]int64 `json:"sources_count"`
	ExpiredEntries   int64            `json:"expired_entries"`
	LastUpdated      time.Time        `json:"last_updated"`
}

// ListSearchQuery represents search parameters for list entries
type ListSearchQuery struct {
	Type       *ListType     `json:"type,omitempty"`
	Category   *ListCategory `json:"category,omitempty"`
	Source     *ListSource   `json:"source,omitempty"`
	Value      string        `json:"value,omitempty"`
	Enabled    *bool         `json:"enabled,omitempty"`
	Limit      int           `json:"limit,omitempty"`
	Offset     int           `json:"offset,omitempty"`
	SortBy     string        `json:"sort_by,omitempty"`
	SortOrder  string        `json:"sort_order,omitempty"`
}

// BulkOperation represents a bulk operation on list entries
type BulkOperation struct {
	Operation string   `json:"operation"` // "add", "remove", "enable", "disable"
	Entries   []string `json:"entries"`   // List of values or IDs
	Category  string   `json:"category,omitempty"`
	Source    string   `json:"source,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// ImportResult represents the result of importing list entries
type ImportResult struct {
	TotalProcessed int      `json:"total_processed"`
	Added          int      `json:"added"`
	Updated        int      `json:"updated"`
	Skipped        int      `json:"skipped"`
	Errors         int      `json:"errors"`
	ErrorMessages  []string `json:"error_messages,omitempty"`
}

// ExportFormat defines the format for exporting lists
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
	FormatTXT  ExportFormat = "txt"
)

// ListCheckResult represents the result of checking a value against lists
type ListCheckResult struct {
	Found       bool       `json:"found"`
	ListType    ListType   `json:"list_type"`
	Entry       *ListEntry `json:"entry,omitempty"`
	Action      string     `json:"action"` // "allow", "block"
	Reason      string     `json:"reason"`
	Timestamp   time.Time  `json:"timestamp"`
}