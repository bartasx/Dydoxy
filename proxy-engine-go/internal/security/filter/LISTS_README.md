# Blacklist/Whitelist Management System

## Overview

The Blacklist/Whitelist Management System provides comprehensive management of security lists for the Dydoxy proxy system. It supports multiple list types, categories, sources, and automatic synchronization with threat intelligence feeds.

## Features

- **Dual List Types**: Blacklist (block) and Whitelist (allow) entries
- **Multiple Categories**: Malware, Phishing, Adult, Gambling, Social Media, etc.
- **Various Sources**: Manual, Threat Feeds, AI Detection, Community, Commercial
- **Bulk Operations**: Import, export, enable/disable multiple entries
- **Threat Feed Integration**: Automatic synchronization with external feeds
- **Expiration Support**: Time-based entry expiration
- **Statistics & Monitoring**: Real-time statistics and reporting
- **REST API**: Complete API for list management

## List Types

### Blacklist (`ListTypeBlacklist = 0`)
Entries that should be blocked. When a request matches a blacklist entry, it will be denied.

### Whitelist (`ListTypeWhitelist = 1`)
Entries that should be explicitly allowed. Whitelist entries take precedence over blacklist entries.

## Categories

- **Malware** (`CategoryMalware`): Known malware domains and URLs
- **Phishing** (`CategoryPhishing`): Phishing and scam sites
- **Adult** (`CategoryAdult`): Adult content sites
- **Gambling** (`CategoryGambling`): Online gambling sites
- **Social Media** (`CategorySocialMedia`): Social media platforms
- **Streaming** (`CategoryStreaming`): Video/audio streaming services
- **News** (`CategoryNews`): News and media sites
- **Shopping** (`CategoryShopping`): E-commerce sites
- **Education** (`CategoryEducation`): Educational resources
- **Business** (`CategoryBusiness`): Business and productivity tools
- **Custom** (`CategoryCustom`): Custom user-defined categories

## Sources

- **Manual** (`SourceManual`): Manually added entries
- **Threat Feed** (`SourceThreatFeed`): External threat intelligence feeds
- **AI Detection** (`SourceAI`): AI-powered threat detection
- **Community** (`SourceCommunity`): Community-contributed entries
- **Commercial** (`SourceCommercial`): Commercial threat intelligence

## API Endpoints

### List Entries Management

#### Get All Entries
```http
GET /api/v1/lists/entries
GET /api/v1/lists/entries?type=0&category=malware&limit=100&offset=0
```

Query Parameters:
- `type`: List type (0=blacklist, 1=whitelist)
- `category`: Entry category
- `source`: Entry source
- `value`: Search by value (partial match)
- `enabled`: Filter by enabled status
- `limit`: Number of results per page
- `offset`: Pagination offset
- `sort_by`: Sort field
- `sort_order`: Sort order (asc/desc)

#### Create Entry
```http
POST /api/v1/lists/entries
Content-Type: application/json

{
  "value": "malware.com",
  "type": 0,
  "category": "malware",
  "source": "manual",
  "reason": "Known malware domain",
  "enabled": true,
  "expires_at": "2024-12-31T23:59:59Z",
  "metadata": {
    "severity": "high",
    "confidence": 0.95
  }
}
```

#### Get Specific Entry
```http
GET /api/v1/lists/entries/{id}
```

#### Update Entry
```http
PUT /api/v1/lists/entries/{id}
Content-Type: application/json

{
  "enabled": false,
  "reason": "Updated reason"
}
```

#### Delete Entry
```http
DELETE /api/v1/lists/entries/{id}
```

### Bulk Operations

#### Bulk Add/Remove/Enable/Disable
```http
POST /api/v1/lists/entries/bulk
Content-Type: application/json

{
  "operation": "add",
  "entries": ["domain1.com", "domain2.com"],
  "category": "malware",
  "source": "manual",
  "reason": "Bulk import from security team"
}
```

Operations:
- `add`: Add new entries
- `remove`: Remove entries (by ID)
- `enable`: Enable entries (by ID)
- `disable`: Disable entries (by ID)

#### Import Entries
```http
POST /api/v1/lists/entries/import
Content-Type: application/json

{
  "type": 0,
  "category": "malware",
  "source": "threat_feed",
  "entries": [
    "malware1.com",
    "malware2.com",
    "malware3.com"
  ]
}
```

#### Export Entries
```http
GET /api/v1/lists/entries/export?format=json&type=0&category=malware
GET /api/v1/lists/entries/export?format=csv&type=1
GET /api/v1/lists/entries/export?format=txt
```

Formats:
- `json`: JSON format with full entry details
- `csv`: CSV format for spreadsheet import
- `txt`: Plain text format (values only)

### List Checking

#### Check Value
```http
POST /api/v1/lists/check
Content-Type: application/json

{
  "value": "suspicious-domain.com"
}
```

Response:
```json
{
  "value": "suspicious-domain.com",
  "result": {
    "found": true,
    "list_type": 0,
    "entry": {
      "id": "entry-123",
      "value": "suspicious-domain.com",
      "type": 0,
      "category": "malware",
      "source": "threat_feed",
      "reason": "Malware domain from ThreatFeed",
      "enabled": true,
      "created_at": "2024-01-15T10:00:00Z"
    },
    "action": "block",
    "reason": "Found in blacklist (Category: malware)",
    "timestamp": "2024-01-15T15:30:00Z"
  }
}
```

### Statistics & Monitoring

#### Get Statistics
```http
GET /api/v1/lists/stats
```

Response:
```json
{
  "stats": {
    "blacklist_entries": 15000,
    "whitelist_entries": 500,
    "categories_count": {
      "malware": 8000,
      "phishing": 4000,
      "adult": 2000,
      "gambling": 1000
    },
    "sources_count": {
      "threat_feed": 12000,
      "manual": 2000,
      "ai_detection": 1500
    },
    "expired_entries": 50,
    "last_updated": "2024-01-15T15:30:00Z"
  }
}
```

### Maintenance

#### Cleanup Expired Entries
```http
POST /api/v1/lists/cleanup
```

Response:
```json
{
  "message": "Cleanup completed",
  "removed": 25
}
```

#### Sync Threat Feeds
```http
POST /api/v1/lists/sync
```

Response:
```json
{
  "message": "Threat feeds synchronized successfully"
}
```

## Usage Examples

### Basic Integration

```go
package main

import (
    "context"
    "github.com/go-redis/redis/v9"
    "github.com/sirupsen/logrus"
    "github.com/dydoxy/proxy-engine-go/internal/security/filter"
)

func main() {
    logger := logrus.New()
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })
    
    // Create list manager
    storage := filter.NewRedisListStorage(redisClient)
    manager := filter.NewManager(storage, logger)
    
    // Add blacklist entry
    entry := &filter.ListEntry{
        Value:    "malware.com",
        Type:     filter.ListTypeBlacklist,
        Category: string(filter.CategoryMalware),
        Source:   string(filter.SourceManual),
        Reason:   "Known malware domain",
        Enabled:  true,
    }
    
    ctx := context.Background()
    manager.AddEntry(ctx, entry)
    
    // Check value
    result, err := manager.CheckValue(ctx, "malware.com")
    if err != nil {
        logger.Error(err)
        return
    }
    
    if result.Found && result.ListType == filter.ListTypeBlacklist {
        logger.Warnf("Domain blocked: %s", result.Reason)
    }
}
```

### Threat Feed Integration

```go
// Register threat feed providers
malwareFeed := filter.NewMalwareDomainsThreatFeed(logger)
phishingFeed := filter.NewPhishingDomainsThreatFeed(logger)

manager.RegisterThreatFeedProvider(malwareFeed)
manager.RegisterThreatFeedProvider(phishingFeed)

// Sync with threat feeds
err := manager.SyncWithThreatFeeds(ctx)
if err != nil {
    logger.Errorf("Failed to sync threat feeds: %v", err)
}
```

### Custom Threat Feed

```go
// Create custom parser function
parser := func(data []byte) ([]*filter.ListEntry, error) {
    lines := strings.Split(string(data), "\n")
    var entries []*filter.ListEntry
    
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        entry := &filter.ListEntry{
            ID:        uuid.New().String(),
            Value:     line,
            Type:      filter.ListTypeBlacklist,
            Category:  string(filter.CategoryMalware),
            Source:    string(filter.SourceThreatFeed),
            Enabled:   true,
            CreatedAt: time.Now(),
            UpdatedAt: time.Now(),
        }
        entries = append(entries, entry)
    }
    
    return entries, nil
}

// Create custom threat feed
customFeed := filter.NewCustomThreatFeed(
    "CustomMalwareFeed",
    "https://example.com/malware-domains.txt",
    parser,
    logger,
)

manager.RegisterThreatFeedProvider(customFeed)
```

## Integration with Content Filter

The list manager integrates seamlessly with the content filtering engine:

```go
// Create content filter with list manager
contentFilter := filter.NewEngineWithLists(filterStorage, listManager, logger)

// The filter will automatically check blacklist/whitelist before applying rules
result, err := contentFilter.Filter(ctx, request)
```

## Performance Considerations

- **Caching**: Frequently accessed entries are cached in memory
- **Indexing**: Redis indexes by type, category, and source for fast queries
- **Bulk Operations**: Use bulk operations for large imports/exports
- **Expiration**: Automatic cleanup of expired entries
- **Pagination**: Use limit/offset for large result sets

## Security Features

- **Input Validation**: All entries are validated before storage
- **Audit Logging**: All operations are logged for compliance
- **Access Control**: API endpoints can be secured with authentication
- **Data Integrity**: Atomic operations ensure data consistency
- **Backup**: Redis persistence ensures data durability

## Monitoring & Alerting

The system provides comprehensive monitoring:

- **Entry Statistics**: Count by type, category, source
- **Performance Metrics**: Response times, cache hit rates
- **Error Tracking**: Failed operations and sync errors
- **Threat Feed Status**: Last sync times and success rates
- **Capacity Monitoring**: Storage usage and growth trends

## Configuration

Environment variables:
- `THREAT_FEED_SYNC_INTERVAL`: How often to sync feeds (default: 1h)
- `LIST_CACHE_SIZE`: Maximum number of cached entries (default: 10000)
- `LIST_CACHE_TTL`: Cache entry TTL (default: 5m)
- `BULK_OPERATION_LIMIT`: Maximum entries per bulk operation (default: 1000)

## Future Enhancements

- **Machine Learning**: AI-powered threat detection and categorization
- **Reputation Scoring**: Dynamic scoring based on multiple sources
- **Geographic Filtering**: Location-based list management
- **Custom Webhooks**: Real-time notifications for list changes
- **Advanced Analytics**: Trend analysis and threat intelligence
- **Federation**: Sharing lists across multiple Dydoxy instances