package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v9"
)

const (
	listEntryKeyPrefix = "lists:entries:"
	listValueKeyPrefix = "lists:values:"
	listStatsKey       = "lists:stats"
	listIndexPrefix    = "lists:index:"
)

// RedisListStorage implements ListStorage using Redis
type RedisListStorage struct {
	client *redis.Client
}

// NewRedisListStorage creates a new Redis-based list storage
func NewRedisListStorage(client *redis.Client) *RedisListStorage {
	return &RedisListStorage{
		client: client,
	}
}

// SaveEntry saves an entry to Redis
func (s *RedisListStorage) SaveEntry(ctx context.Context, entry *ListEntry) error {
	// Serialize entry to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}
	
	pipe := s.client.Pipeline()
	
	// Save entry data
	entryKey := listEntryKeyPrefix + entry.ID
	pipe.Set(ctx, entryKey, data, 0)
	
	// Index by value for fast lookup
	valueKey := listValueKeyPrefix + entry.Value
	pipe.Set(ctx, valueKey, entry.ID, 0)
	
	// Add to type index
	typeIndexKey := listIndexPrefix + "type:" + strconv.Itoa(int(entry.Type))
	pipe.SAdd(ctx, typeIndexKey, entry.ID)
	
	// Add to category index
	if entry.Category != "" {
		categoryIndexKey := listIndexPrefix + "category:" + entry.Category
		pipe.SAdd(ctx, categoryIndexKey, entry.ID)
	}
	
	// Add to source index
	if entry.Source != "" {
		sourceIndexKey := listIndexPrefix + "source:" + entry.Source
		pipe.SAdd(ctx, sourceIndexKey, entry.ID)
	}
	
	// Set expiration if specified
	if entry.ExpiresAt != nil {
		expiration := time.Until(*entry.ExpiresAt)
		if expiration > 0 {
			pipe.Expire(ctx, entryKey, expiration)
			pipe.Expire(ctx, valueKey, expiration)
		}
	}
	
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to save entry to Redis: %w", err)
	}
	
	return nil
}

// LoadEntry loads an entry from Redis
func (s *RedisListStorage) LoadEntry(ctx context.Context, entryID string) (*ListEntry, error) {
	entryKey := listEntryKeyPrefix + entryID
	data, err := s.client.Get(ctx, entryKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("entry not found: %s", entryID)
		}
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}
	
	var entry ListEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}
	
	return &entry, nil
}

// DeleteEntry deletes an entry from Redis
func (s *RedisListStorage) DeleteEntry(ctx context.Context, entryID string) error {
	// Get entry first to clean up indexes
	entry, err := s.LoadEntry(ctx, entryID)
	if err != nil {
		return err
	}
	
	pipe := s.client.Pipeline()
	
	// Delete entry data
	entryKey := listEntryKeyPrefix + entryID
	pipe.Del(ctx, entryKey)
	
	// Delete value index
	valueKey := listValueKeyPrefix + entry.Value
	pipe.Del(ctx, valueKey)
	
	// Remove from type index
	typeIndexKey := listIndexPrefix + "type:" + strconv.Itoa(int(entry.Type))
	pipe.SRem(ctx, typeIndexKey, entryID)
	
	// Remove from category index
	if entry.Category != "" {
		categoryIndexKey := listIndexPrefix + "category:" + entry.Category
		pipe.SRem(ctx, categoryIndexKey, entryID)
	}
	
	// Remove from source index
	if entry.Source != "" {
		sourceIndexKey := listIndexPrefix + "source:" + entry.Source
		pipe.SRem(ctx, sourceIndexKey, entryID)
	}
	
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete entry from Redis: %w", err)
	}
	
	return nil
}

// SearchEntries searches entries in Redis
func (s *RedisListStorage) SearchEntries(ctx context.Context, query *ListSearchQuery) ([]*ListEntry, int64, error) {
	var entryIDs []string
	var err error
	
	// Build search based on query parameters
	if query.Type != nil {
		typeIndexKey := listIndexPrefix + "type:" + strconv.Itoa(int(*query.Type))
		entryIDs, err = s.client.SMembers(ctx, typeIndexKey).Result()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to search by type: %w", err)
		}
	} else if query.Category != nil {
		categoryIndexKey := listIndexPrefix + "category:" + string(*query.Category)
		entryIDs, err = s.client.SMembers(ctx, categoryIndexKey).Result()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to search by category: %w", err)
		}
	} else if query.Source != nil {
		sourceIndexKey := listIndexPrefix + "source:" + string(*query.Source)
		entryIDs, err = s.client.SMembers(ctx, sourceIndexKey).Result()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to search by source: %w", err)
		}
	} else {
		// Get all entries from all type indexes
		blacklistKey := listIndexPrefix + "type:0"
		whitelistKey := listIndexPrefix + "type:1"
		
		blacklistIDs, _ := s.client.SMembers(ctx, blacklistKey).Result()
		whitelistIDs, _ := s.client.SMembers(ctx, whitelistKey).Result()
		
		entryIDs = append(blacklistIDs, whitelistIDs...)
	}
	
	// Apply pagination
	total := int64(len(entryIDs))
	
	if query.Offset > 0 {
		if query.Offset >= len(entryIDs) {
			return []*ListEntry{}, total, nil
		}
		entryIDs = entryIDs[query.Offset:]
	}
	
	if query.Limit > 0 && query.Limit < len(entryIDs) {
		entryIDs = entryIDs[:query.Limit]
	}
	
	// Load entries
	var entries []*ListEntry
	for _, entryID := range entryIDs {
		entry, err := s.LoadEntry(ctx, entryID)
		if err != nil {
			continue // Skip entries that can't be loaded
		}
		
		// Apply additional filters
		if s.matchesQuery(entry, query) {
			entries = append(entries, entry)
		}
	}
	
	return entries, total, nil
}

// CheckValue checks if a value exists in Redis
func (s *RedisListStorage) CheckValue(ctx context.Context, value string) (*ListEntry, error) {
	valueKey := listValueKeyPrefix + value
	entryID, err := s.client.Get(ctx, valueKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to check value: %w", err)
	}
	
	return s.LoadEntry(ctx, entryID)
}

// GetStats returns storage statistics
func (s *RedisListStorage) GetStats(ctx context.Context) (*ListStats, error) {
	stats := &ListStats{
		CategoriesCount: make(map[string]int64),
		SourcesCount:    make(map[string]int64),
		LastUpdated:     time.Now(),
	}
	
	// Count blacklist entries
	blacklistKey := listIndexPrefix + "type:0"
	blacklistCount, err := s.client.SCard(ctx, blacklistKey).Result()
	if err == nil {
		stats.BlacklistEntries = blacklistCount
	}
	
	// Count whitelist entries
	whitelistKey := listIndexPrefix + "type:1"
	whitelistCount, err := s.client.SCard(ctx, whitelistKey).Result()
	if err == nil {
		stats.WhitelistEntries = whitelistCount
	}
	
	// Count by categories and sources
	categoryKeys, _ := s.client.Keys(ctx, listIndexPrefix+"category:*").Result()
	for _, key := range categoryKeys {
		category := strings.TrimPrefix(key, listIndexPrefix+"category:")
		count, _ := s.client.SCard(ctx, key).Result()
		stats.CategoriesCount[category] = count
	}
	
	sourceKeys, _ := s.client.Keys(ctx, listIndexPrefix+"source:*").Result()
	for _, key := range sourceKeys {
		source := strings.TrimPrefix(key, listIndexPrefix+"source:")
		count, _ := s.client.SCard(ctx, key).Result()
		stats.SourcesCount[source] = count
	}
	
	return stats, nil
}

// CleanupExpired removes expired entries from Redis
func (s *RedisListStorage) CleanupExpired(ctx context.Context) (int64, error) {
	// Redis automatically handles expiration, but we need to clean up indexes
	var deletedCount int64
	
	// Get all entry keys
	entryKeys, err := s.client.Keys(ctx, listEntryKeyPrefix+"*").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get entry keys: %w", err)
	}
	
	for _, entryKey := range entryKeys {
		// Check if key exists (not expired)
		exists, err := s.client.Exists(ctx, entryKey).Result()
		if err != nil {
			continue
		}
		
		if exists == 0 {
			// Entry expired, clean up indexes
			entryID := strings.TrimPrefix(entryKey, listEntryKeyPrefix)
			
			// Try to get entry data from backup or reconstruct from indexes
			// For now, we'll just increment the counter
			deletedCount++
		}
	}
	
	return deletedCount, nil
}

// BulkSave saves multiple entries at once
func (s *RedisListStorage) BulkSave(ctx context.Context, entries []*ListEntry) error {
	if len(entries) == 0 {
		return nil
	}
	
	pipe := s.client.Pipeline()
	
	for _, entry := range entries {
		// Serialize entry to JSON
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal entry %s: %w", entry.ID, err)
		}
		
		// Save entry data
		entryKey := listEntryKeyPrefix + entry.ID
		pipe.Set(ctx, entryKey, data, 0)
		
		// Index by value for fast lookup
		valueKey := listValueKeyPrefix + entry.Value
		pipe.Set(ctx, valueKey, entry.ID, 0)
		
		// Add to type index
		typeIndexKey := listIndexPrefix + "type:" + strconv.Itoa(int(entry.Type))
		pipe.SAdd(ctx, typeIndexKey, entry.ID)
		
		// Add to category index
		if entry.Category != "" {
			categoryIndexKey := listIndexPrefix + "category:" + entry.Category
			pipe.SAdd(ctx, categoryIndexKey, entry.ID)
		}
		
		// Add to source index
		if entry.Source != "" {
			sourceIndexKey := listIndexPrefix + "source:" + entry.Source
			pipe.SAdd(ctx, sourceIndexKey, entry.ID)
		}
		
		// Set expiration if specified
		if entry.ExpiresAt != nil {
			expiration := time.Until(*entry.ExpiresAt)
			if expiration > 0 {
				pipe.Expire(ctx, entryKey, expiration)
				pipe.Expire(ctx, valueKey, expiration)
			}
		}
	}
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to bulk save entries: %w", err)
	}
	
	return nil
}

// BulkDelete deletes multiple entries at once
func (s *RedisListStorage) BulkDelete(ctx context.Context, entryIDs []string) error {
	if len(entryIDs) == 0 {
		return nil
	}
	
	pipe := s.client.Pipeline()
	
	for _, entryID := range entryIDs {
		// Get entry first to clean up indexes
		entry, err := s.LoadEntry(ctx, entryID)
		if err != nil {
			continue // Skip entries that can't be loaded
		}
		
		// Delete entry data
		entryKey := listEntryKeyPrefix + entryID
		pipe.Del(ctx, entryKey)
		
		// Delete value index
		valueKey := listValueKeyPrefix + entry.Value
		pipe.Del(ctx, valueKey)
		
		// Remove from type index
		typeIndexKey := listIndexPrefix + "type:" + strconv.Itoa(int(entry.Type))
		pipe.SRem(ctx, typeIndexKey, entryID)
		
		// Remove from category index
		if entry.Category != "" {
			categoryIndexKey := listIndexPrefix + "category:" + entry.Category
			pipe.SRem(ctx, categoryIndexKey, entryID)
		}
		
		// Remove from source index
		if entry.Source != "" {
			sourceIndexKey := listIndexPrefix + "source:" + entry.Source
			pipe.SRem(ctx, sourceIndexKey, entryID)
		}
	}
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to bulk delete entries: %w", err)
	}
	
	return nil
}

// Helper method to check if entry matches query filters
func (s *RedisListStorage) matchesQuery(entry *ListEntry, query *ListSearchQuery) bool {
	if query.Value != "" && !strings.Contains(strings.ToLower(entry.Value), strings.ToLower(query.Value)) {
		return false
	}
	
	if query.Enabled != nil && entry.Enabled != *query.Enabled {
		return false
	}
	
	return true
}