# Content Filtering Engine

## Overview

The Content Filtering Engine provides comprehensive content filtering capabilities for the Dydoxy proxy system. It supports multiple rule types, real-time filtering, and flexible actions.

## Features

- **Multiple Rule Types**: URL, Domain, Keyword, Regex, Content-Type, File Extension
- **Flexible Actions**: Allow, Block, Log, Quarantine
- **Priority-based Processing**: Rules are processed by priority (higher first)
- **Real-time Filtering**: Integrated with proxy middleware
- **Redis Storage**: Persistent rule storage with Redis backend
- **REST API**: Complete API for rule management
- **Statistics**: Real-time filtering statistics
- **Testing**: Built-in filter testing capabilities

## Rule Types

### 1. Domain Rules (`RuleTypeDomain`)
Matches against request domains with support for subdomains.

```json
{
  "name": "Block Social Media",
  "pattern": "facebook.com",
  "type": 1,
  "action": 1
}
```

### 2. URL Rules (`RuleTypeURL`)
Matches against full URLs using substring matching.

```json
{
  "name": "Block Admin Panels",
  "pattern": "/admin",
  "type": 0,
  "action": 1
}
```

### 3. Keyword Rules (`RuleTypeKeyword`)
Matches keywords in URLs, headers, or content body.

```json
{
  "name": "Block Gambling Content",
  "pattern": "gambling",
  "type": 2,
  "action": 1
}
```

### 4. Regex Rules (`RuleTypeRegex`)
Uses regular expressions for complex pattern matching.

```json
{
  "name": "Block IP Addresses",
  "pattern": "\\d+\\.\\d+\\.\\d+\\.\\d+",
  "type": 3,
  "action": 1
}
```

### 5. Content-Type Rules (`RuleTypeContentType`)
Matches against HTTP Content-Type headers.

```json
{
  "name": "Block Video Content",
  "pattern": "video/",
  "type": 4,
  "action": 1
}
```

### 6. File Extension Rules (`RuleTypeFileExtension`)
Matches against file extensions in URLs.

```json
{
  "name": "Block Executables",
  "pattern": ".exe",
  "type": 5,
  "action": 1
}
```

## Actions

- **ActionAllow (0)**: Allow the request to proceed
- **ActionBlock (1)**: Block the request and return 403
- **ActionLog (2)**: Allow the request but log it for monitoring
- **ActionQuarantine (3)**: Block the request and quarantine for review

## API Endpoints

### Get All Rules
```http
GET /api/v1/filter/rules
GET /api/v1/filter/rules?type=1  # Filter by rule type
```

### Create Rule
```http
POST /api/v1/filter/rules
Content-Type: application/json

{
  "name": "Block Malware",
  "pattern": "malware.com",
  "type": 1,
  "action": 1,
  "priority": 1000,
  "enabled": true,
  "description": "Blocks known malware domain"
}
```

### Get Specific Rule
```http
GET /api/v1/filter/rules/{id}
```

### Update Rule
```http
PUT /api/v1/filter/rules/{id}
Content-Type: application/json

{
  "name": "Updated Rule Name",
  "enabled": false
}
```

### Delete Rule
```http
DELETE /api/v1/filter/rules/{id}
```

### Reload Rules
```http
POST /api/v1/filter/rules/reload
```

### Get Statistics
```http
GET /api/v1/filter/stats
```

Response:
```json
{
  "stats": {
    "total_requests": 1000,
    "blocked_requests": 50,
    "allowed_requests": 900,
    "logged_requests": 50
  }
}
```

### Test Filter
```http
POST /api/v1/filter/test
Content-Type: application/json

{
  "url": "https://example.com/test",
  "domain": "example.com",
  "method": "GET",
  "user_id": "user123",
  "org_id": "org456"
}
```

Response:
```json
{
  "request": {
    "url": "https://example.com/test",
    "domain": "example.com",
    "method": "GET",
    "user_id": "user123",
    "org_id": "org456"
  },
  "result": {
    "allowed": true,
    "action": 0,
    "reason": "No matching rules",
    "timestamp": "2024-01-15T10:30:00Z"
  }
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
    
    // Create filter engine
    storage := filter.NewRedisStorage(redisClient)
    contentFilter := filter.NewEngine(storage, logger)
    
    // Create a rule
    rule := &filter.FilterRule{
        ID:       "block-malware",
        Name:     "Block Malware",
        Pattern:  "malware.com",
        Type:     filter.RuleTypeDomain,
        Action:   filter.ActionBlock,
        Priority: 1000,
        Enabled:  true,
    }
    
    // Add rule
    ctx := context.Background()
    contentFilter.AddRule(ctx, rule)
    
    // Test filtering
    request := &filter.ContentRequest{
        URL:    "https://malware.com/evil",
        Domain: "malware.com",
        UserID: "user123",
    }
    
    result, err := contentFilter.Filter(ctx, request)
    if err != nil {
        logger.Error(err)
        return
    }
    
    if !result.Allowed {
        logger.Warnf("Request blocked: %s", result.Reason)
    }
}
```

### Middleware Integration

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/dydoxy/proxy-engine-go/internal/security/filter"
)

func main() {
    r := gin.Default()
    
    // Add content filtering middleware
    filterMiddleware := filter.NewMiddleware(contentFilter, logger)
    r.Use(filterMiddleware.GinMiddleware())
    
    // Your routes here
    r.GET("/proxy", proxyHandler)
    
    r.Run(":8080")
}
```

## Configuration

The content filter can be configured through environment variables:

- `REDIS_ADDR`: Redis server address (default: localhost:6379)
- `REDIS_PASSWORD`: Redis password
- `REDIS_DB`: Redis database number (default: 0)

## Performance Considerations

- Rules are cached in memory for fast processing
- Rules are sorted by priority for optimal performance
- Redis is used for persistent storage and distributed deployments
- Regex patterns are compiled and cached
- Statistics are updated atomically

## Security Features

- Input validation for all rule parameters
- SQL injection protection through parameterized queries
- XSS protection in API responses
- Rate limiting integration
- Audit logging for all rule changes

## Testing

Run tests with:
```bash
go test ./internal/security/filter/...
```

The test suite includes:
- Unit tests for all matchers
- Integration tests with Redis
- Performance benchmarks
- Mock implementations for testing

## Monitoring

The filter engine provides comprehensive monitoring:

- Request/response statistics
- Rule match statistics
- Performance metrics
- Error tracking
- Audit logs

## Future Enhancements

- Machine learning-based content classification
- Integration with threat intelligence feeds
- Advanced regex optimization
- Content scanning for malware
- Behavioral analysis
- Custom rule scripting