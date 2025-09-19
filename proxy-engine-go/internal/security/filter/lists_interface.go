package filter

import (
	"context"
	"io"
)

// ListManager defines the interface for managing blacklists and whitelists
type ListManager interface {
	// AddEntry adds a new entry to a list
	AddEntry(ctx context.Context, entry *ListEntry) error
	
	// RemoveEntry removes an entry from a list by ID
	RemoveEntry(ctx context.Context, entryID string) error
	
	// UpdateEntry updates an existing list entry
	UpdateEntry(ctx context.Context, entry *ListEntry) error
	
	// GetEntry retrieves a specific entry by ID
	GetEntry(ctx context.Context, entryID string) (*ListEntry, error)
	
	// SearchEntries searches for entries based on query parameters
	SearchEntries(ctx context.Context, query *ListSearchQuery) ([]*ListEntry, int64, error)
	
	// CheckValue checks if a value exists in blacklist or whitelist
	CheckValue(ctx context.Context, value string) (*ListCheckResult, error)
	
	// BulkOperation performs bulk operations on list entries
	BulkOperation(ctx context.Context, operation *BulkOperation) (*ImportResult, error)
	
	// ImportEntries imports entries from various sources
	ImportEntries(ctx context.Context, listType ListType, source ListSource, entries []string, category ListCategory) (*ImportResult, error)
	
	// ExportEntries exports entries in specified format
	ExportEntries(ctx context.Context, query *ListSearchQuery, format ExportFormat, writer io.Writer) error
	
	// GetStats returns statistics about lists
	GetStats(ctx context.Context) (*ListStats, error)
	
	// CleanupExpired removes expired entries
	CleanupExpired(ctx context.Context) (int64, error)
	
	// SyncWithThreatFeeds synchronizes with external threat intelligence feeds
	SyncWithThreatFeeds(ctx context.Context) error
}

// ListStorage defines the interface for list persistence
type ListStorage interface {
	// SaveEntry saves an entry to storage
	SaveEntry(ctx context.Context, entry *ListEntry) error
	
	// LoadEntry loads an entry from storage
	LoadEntry(ctx context.Context, entryID string) (*ListEntry, error)
	
	// DeleteEntry deletes an entry from storage
	DeleteEntry(ctx context.Context, entryID string) error
	
	// SearchEntries searches entries in storage
	SearchEntries(ctx context.Context, query *ListSearchQuery) ([]*ListEntry, int64, error)
	
	// CheckValue checks if a value exists in storage
	CheckValue(ctx context.Context, value string) (*ListEntry, error)
	
	// GetStats returns storage statistics
	GetStats(ctx context.Context) (*ListStats, error)
	
	// CleanupExpired removes expired entries from storage
	CleanupExpired(ctx context.Context) (int64, error)
	
	// BulkSave saves multiple entries at once
	BulkSave(ctx context.Context, entries []*ListEntry) error
	
	// BulkDelete deletes multiple entries at once
	BulkDelete(ctx context.Context, entryIDs []string) error
}

// ThreatFeedProvider defines the interface for threat intelligence feeds
type ThreatFeedProvider interface {
	// GetName returns the name of the threat feed provider
	GetName() string
	
	// FetchEntries fetches entries from the threat feed
	FetchEntries(ctx context.Context) ([]*ListEntry, error)
	
	// GetLastUpdate returns the timestamp of the last update
	GetLastUpdate() time.Time
	
	// IsEnabled returns whether the provider is enabled
	IsEnabled() bool
}