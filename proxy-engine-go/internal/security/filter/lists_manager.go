package filter

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Manager implements the ListManager interface
type Manager struct {
	storage   ListStorage
	providers map[string]ThreatFeedProvider
	logger    *logrus.Logger
	mu        sync.RWMutex
	cache     map[string]*ListEntry // Simple in-memory cache
}

// NewManager creates a new list manager
func NewManager(storage ListStorage, logger *logrus.Logger) *Manager {
	return &Manager{
		storage:   storage,
		providers: make(map[string]ThreatFeedProvider),
		logger:    logger,
		cache:     make(map[string]*ListEntry),
	}
}

// RegisterThreatFeedProvider registers a threat feed provider
func (m *Manager) RegisterThreatFeedProvider(provider ThreatFeedProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.providers[provider.GetName()] = provider
	m.logger.Infof("Registered threat feed provider: %s", provider.GetName())
}

// AddEntry adds a new entry to a list
func (m *Manager) AddEntry(ctx context.Context, entry *ListEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	
	if err := m.validateEntry(entry); err != nil {
		return fmt.Errorf("invalid entry: %w", err)
	}
	
	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	
	if err := m.storage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}
	
	// Update cache
	m.mu.Lock()
	m.cache[entry.Value] = entry
	m.mu.Unlock()
	
	m.logger.Infof("Added %s entry: %s (Category: %s)", 
		m.listTypeString(entry.Type), entry.Value, entry.Category)
	
	return nil
}

// RemoveEntry removes an entry from a list by ID
func (m *Manager) RemoveEntry(ctx context.Context, entryID string) error {
	// Get entry first to update cache
	entry, err := m.storage.LoadEntry(ctx, entryID)
	if err != nil {
		return fmt.Errorf("failed to load entry: %w", err)
	}
	
	if err := m.storage.DeleteEntry(ctx, entryID); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}
	
	// Remove from cache
	m.mu.Lock()
	delete(m.cache, entry.Value)
	m.mu.Unlock()
	
	m.logger.Infof("Removed %s entry: %s", 
		m.listTypeString(entry.Type), entry.Value)
	
	return nil
}

// UpdateEntry updates an existing list entry
func (m *Manager) UpdateEntry(ctx context.Context, entry *ListEntry) error {
	if err := m.validateEntry(entry); err != nil {
		return fmt.Errorf("invalid entry: %w", err)
	}
	
	entry.UpdatedAt = time.Now()
	
	if err := m.storage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to update entry: %w", err)
	}
	
	// Update cache
	m.mu.Lock()
	m.cache[entry.Value] = entry
	m.mu.Unlock()
	
	m.logger.Infof("Updated %s entry: %s", 
		m.listTypeString(entry.Type), entry.Value)
	
	return nil
}

// GetEntry retrieves a specific entry by ID
func (m *Manager) GetEntry(ctx context.Context, entryID string) (*ListEntry, error) {
	return m.storage.LoadEntry(ctx, entryID)
}

// SearchEntries searches for entries based on query parameters
func (m *Manager) SearchEntries(ctx context.Context, query *ListSearchQuery) ([]*ListEntry, int64, error) {
	return m.storage.SearchEntries(ctx, query)
}

// CheckValue checks if a value exists in blacklist or whitelist
func (m *Manager) CheckValue(ctx context.Context, value string) (*ListCheckResult, error) {
	// Check cache first
	m.mu.RLock()
	if entry, exists := m.cache[value]; exists {
		m.mu.RUnlock()
		return m.createCheckResult(entry), nil
	}
	m.mu.RUnlock()
	
	// Check storage
	entry, err := m.storage.CheckValue(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("failed to check value: %w", err)
	}
	
	if entry == nil {
		return &ListCheckResult{
			Found:     false,
			Action:    "allow",
			Reason:    "Not found in any list",
			Timestamp: time.Now(),
		}, nil
	}
	
	// Update cache
	m.mu.Lock()
	m.cache[value] = entry
	m.mu.Unlock()
	
	return m.createCheckResult(entry), nil
}

// BulkOperation performs bulk operations on list entries
func (m *Manager) BulkOperation(ctx context.Context, operation *BulkOperation) (*ImportResult, error) {
	result := &ImportResult{
		TotalProcessed: len(operation.Entries),
	}
	
	switch operation.Operation {
	case "add":
		return m.bulkAdd(ctx, operation)
	case "remove":
		return m.bulkRemove(ctx, operation)
	case "enable":
		return m.bulkEnable(ctx, operation, true)
	case "disable":
		return m.bulkEnable(ctx, operation, false)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation.Operation)
	}
}

// ImportEntries imports entries from various sources
func (m *Manager) ImportEntries(ctx context.Context, listType ListType, source ListSource, entries []string, category ListCategory) (*ImportResult, error) {
	result := &ImportResult{
		TotalProcessed: len(entries),
	}
	
	var listEntries []*ListEntry
	
	for _, value := range entries {
		if strings.TrimSpace(value) == "" {
			result.Skipped++
			continue
		}
		
		entry := &ListEntry{
			ID:        uuid.New().String(),
			Value:     strings.TrimSpace(value),
			Type:      listType,
			Category:  string(category),
			Source:    string(source),
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		
		listEntries = append(listEntries, entry)
	}
	
	if err := m.storage.BulkSave(ctx, listEntries); err != nil {
		result.Errors = len(listEntries)
		result.ErrorMessages = append(result.ErrorMessages, err.Error())
		return result, fmt.Errorf("failed to bulk save entries: %w", err)
	}
	
	// Update cache
	m.mu.Lock()
	for _, entry := range listEntries {
		m.cache[entry.Value] = entry
	}
	m.mu.Unlock()
	
	result.Added = len(listEntries)
	
	m.logger.Infof("Imported %d %s entries from %s (Category: %s)", 
		result.Added, m.listTypeString(listType), source, category)
	
	return result, nil
}

// ExportEntries exports entries in specified format
func (m *Manager) ExportEntries(ctx context.Context, query *ListSearchQuery, format ExportFormat, writer io.Writer) error {
	entries, _, err := m.storage.SearchEntries(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to search entries: %w", err)
	}
	
	switch format {
	case FormatJSON:
		return m.exportJSON(entries, writer)
	case FormatCSV:
		return m.exportCSV(entries, writer)
	case FormatTXT:
		return m.exportTXT(entries, writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// GetStats returns statistics about lists
func (m *Manager) GetStats(ctx context.Context) (*ListStats, error) {
	return m.storage.GetStats(ctx)
}

// CleanupExpired removes expired entries
func (m *Manager) CleanupExpired(ctx context.Context) (int64, error) {
	count, err := m.storage.CleanupExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired entries: %w", err)
	}
	
	// Clear cache to force reload
	m.mu.Lock()
	m.cache = make(map[string]*ListEntry)
	m.mu.Unlock()
	
	m.logger.Infof("Cleaned up %d expired entries", count)
	return count, nil
}

// SyncWithThreatFeeds synchronizes with external threat intelligence feeds
func (m *Manager) SyncWithThreatFeeds(ctx context.Context) error {
	m.mu.RLock()
	providers := make([]ThreatFeedProvider, 0, len(m.providers))
	for _, provider := range m.providers {
		if provider.IsEnabled() {
			providers = append(providers, provider)
		}
	}
	m.mu.RUnlock()
	
	var totalAdded int
	
	for _, provider := range providers {
		m.logger.Infof("Syncing with threat feed: %s", provider.GetName())
		
		entries, err := provider.FetchEntries(ctx)
		if err != nil {
			m.logger.Errorf("Failed to fetch from %s: %v", provider.GetName(), err)
			continue
		}
		
		if err := m.storage.BulkSave(ctx, entries); err != nil {
			m.logger.Errorf("Failed to save entries from %s: %v", provider.GetName(), err)
			continue
		}
		
		// Update cache
		m.mu.Lock()
		for _, entry := range entries {
			m.cache[entry.Value] = entry
		}
		m.mu.Unlock()
		
		totalAdded += len(entries)
		m.logger.Infof("Added %d entries from %s", len(entries), provider.GetName())
	}
	
	m.logger.Infof("Threat feed sync completed. Total entries added: %d", totalAdded)
	return nil
}

// Helper methods

func (m *Manager) validateEntry(entry *ListEntry) error {
	if entry.Value == "" {
		return fmt.Errorf("entry value cannot be empty")
	}
	
	if entry.Type != ListTypeBlacklist && entry.Type != ListTypeWhitelist {
		return fmt.Errorf("invalid list type: %v", entry.Type)
	}
	
	return nil
}

func (m *Manager) listTypeString(listType ListType) string {
	switch listType {
	case ListTypeBlacklist:
		return "blacklist"
	case ListTypeWhitelist:
		return "whitelist"
	default:
		return "unknown"
	}
}

func (m *Manager) createCheckResult(entry *ListEntry) *ListCheckResult {
	result := &ListCheckResult{
		Found:     true,
		ListType:  entry.Type,
		Entry:     entry,
		Timestamp: time.Now(),
	}
	
	if entry.Type == ListTypeBlacklist {
		result.Action = "block"
		result.Reason = fmt.Sprintf("Found in blacklist (Category: %s)", entry.Category)
	} else {
		result.Action = "allow"
		result.Reason = fmt.Sprintf("Found in whitelist (Category: %s)", entry.Category)
	}
	
	return result
}

func (m *Manager) bulkAdd(ctx context.Context, operation *BulkOperation) (*ImportResult, error) {
	result := &ImportResult{
		TotalProcessed: len(operation.Entries),
	}
	
	var entries []*ListEntry
	
	for _, value := range operation.Entries {
		entry := &ListEntry{
			ID:        uuid.New().String(),
			Value:     value,
			Type:      ListTypeBlacklist, // Default to blacklist
			Category:  operation.Category,
			Source:    operation.Source,
			Reason:    operation.Reason,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		entries = append(entries, entry)
	}
	
	if err := m.storage.BulkSave(ctx, entries); err != nil {
		result.Errors = len(entries)
		result.ErrorMessages = append(result.ErrorMessages, err.Error())
		return result, err
	}
	
	result.Added = len(entries)
	return result, nil
}

func (m *Manager) bulkRemove(ctx context.Context, operation *BulkOperation) (*ImportResult, error) {
	result := &ImportResult{
		TotalProcessed: len(operation.Entries),
	}
	
	if err := m.storage.BulkDelete(ctx, operation.Entries); err != nil {
		result.Errors = len(operation.Entries)
		result.ErrorMessages = append(result.ErrorMessages, err.Error())
		return result, err
	}
	
	result.Added = len(operation.Entries) // Actually removed
	return result, nil
}

func (m *Manager) bulkEnable(ctx context.Context, operation *BulkOperation, enabled bool) (*ImportResult, error) {
	result := &ImportResult{
		TotalProcessed: len(operation.Entries),
	}
	
	for _, entryID := range operation.Entries {
		entry, err := m.storage.LoadEntry(ctx, entryID)
		if err != nil {
			result.Errors++
			result.ErrorMessages = append(result.ErrorMessages, 
				fmt.Sprintf("Failed to load entry %s: %v", entryID, err))
			continue
		}
		
		entry.Enabled = enabled
		entry.UpdatedAt = time.Now()
		
		if err := m.storage.SaveEntry(ctx, entry); err != nil {
			result.Errors++
			result.ErrorMessages = append(result.ErrorMessages, 
				fmt.Sprintf("Failed to update entry %s: %v", entryID, err))
			continue
		}
		
		result.Updated++
	}
	
	return result, nil
}

func (m *Manager) exportJSON(entries []*ListEntry, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

func (m *Manager) exportCSV(entries []*ListEntry, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	
	// Write header
	header := []string{"ID", "Value", "Type", "Category", "Source", "Reason", "Enabled", "CreatedAt"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	
	// Write entries
	for _, entry := range entries {
		record := []string{
			entry.ID,
			entry.Value,
			m.listTypeString(entry.Type),
			entry.Category,
			entry.Source,
			entry.Reason,
			fmt.Sprintf("%t", entry.Enabled),
			entry.CreatedAt.Format(time.RFC3339),
		}
		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}
	
	return nil
}

func (m *Manager) exportTXT(entries []*ListEntry, writer io.Writer) error {
	for _, entry := range entries {
		if _, err := fmt.Fprintf(writer, "%s\n", entry.Value); err != nil {
			return err
		}
	}
	return nil
}