# Token Bucket Rate Limiting System

## Overview

The Token Bucket Rate Limiting System provides advanced, multi-layered rate limiting capabilities for the Dydoxy proxy system. It implements the token bucket algorithm with support for multiple strategies, Redis persistence, and real-time monitoring.

## Features

- **Token Bucket Algorithm**: Efficient and flexible rate limiting
- **Multi-Layer Strategies**: Per-user, per-IP, per-organization, per-endpoint, composite, size-based, and tiered limiting
- **Redis Persistence**: Distributed rate limiting across multiple instances
- **Real-time Monitoring**: Live statistics and bucket information
- **Configurable Policies**: Dynamic configuration management
- **Middleware Integration**: Easy integration with HTTP servers
- **REST API**: Complete API for management and monitoring

## Token Bucket Algorithm

The token bucket algorithm works by:

1. **Bucket**: Contains a limited number of tokens (capacity)
2. **Refill**: Tokens are added at a constant rate (refill rate)
3. **Consumption**: Each request consumes one or more tokens
4. **Allow/Deny**: Requests are allowed if sufficient tokens are available

### Advantages

- **Burst Handling**: Allows bursts up to bucket capacity
- **Smooth Rate Limiting**: Provides consistent long-term rate limiting
- **Flexible**: Supports different token costs per request
- **Efficient**: O(1) time complexity for rate limit checks

## Rate Limiting Strategies

### 1. Per-User Strategy (`PerUserStrategy`)
Limits requests per individual user.

```go
strategy := ratelimit.NewPerUserStrategy("user_config")
// Bucket key: "user:{user_id}"
```

### 2. Per-IP Strategy (`PerIPStrategy`)
Limits requests per IP address.

```go
strategy := ratelimit.NewPerIPStrategy("ip_config")
// Bucket key: "ip:{ip_address}"
```

### 3. Per-Organization Strategy (`PerOrgStrategy`)
Limits requests per organization.

```go
strategy := ratelimit.NewPerOrgStrategy("org_config")
// Bucket key: "org:{org_id}"
```

### 4. Per-Endpoint Strategy (`PerEndpointStrategy`)
Limits requests per API endpoint.

```go
strategy := ratelimit.NewPerEndpointStrategy("endpoint_config")
// Bucket key: "endpoint:{method}:{endpoint}"
```

### 5. Composite Strategy (`CompositeStrategy`)
Combines user and IP for more granular control.

```go
strategy := ratelimit.NewCompositeStrategy("composite_config")
// Bucket key: "composite:{user_id}:{ip_address}"
```

### 6. Size-Based Strategy (`SizeBasedStrategy`)
Consumes tokens based on request size.

```go
strategy := ratelimit.NewSizeBasedStrategy("size_config", 1024, 1) // 1KB per token, min 1 token
// Tokens required: max(request_size / bytes_per_token, min_tokens)
```

### 7. Tiered Strategy (`TieredStrategy`)
Uses different configurations based on user tier.

```go
tierConfigs := map[string]string{
    "premium": "premium_config",
    "basic":   "basic_config",
}
strategy := ratelimit.NewTieredStrategy(tierConfigs, "default_config")
```

## Configuration

### Bucket Configuration

```go
config := &ratelimit.BucketConfig{
    Capacity:      100,  // Maximum tokens in bucket
    RefillRate:    10,   // Tokens added per second
    InitialTokens: 50,   // Initial token count (optional)
}
```

### Common Configurations

```go
// API rate limiting (100 requests per minute)
apiConfig := &ratelimit.BucketConfig{
    Capacity:   100,
    RefillRate: 100 / 60, // ~1.67 tokens per second
}

// Burst-friendly (allows 1000 requests burst, then 10/second)
burstConfig := &ratelimit.BucketConfig{
    Capacity:   1000,
    RefillRate: 10,
}

// Strict limiting (10 requests per second, no burst)
strictConfig := &ratelimit.BucketConfig{
    Capacity:   10,
    RefillRate: 10,
}
```

## API Endpoints

### Configuration Management

#### Get All Configurations
```http
GET /api/v1/ratelimit/configs
```

#### Create Configuration
```http
POST /api/v1/ratelimit/configs
Content-Type: application/json

{
  "name": "api_limit",
  "capacity": 1000,
  "refill_rate": 50,
  "initial_tokens": 500
}
```

#### Get Specific Configuration
```http
GET /api/v1/ratelimit/configs/{name}
```

#### Update Configuration
```http
PUT /api/v1/ratelimit/configs/{name}
Content-Type: application/json

{
  "capacity": 2000,
  "refill_rate": 100
}
```

### Bucket Management

#### Get All Buckets
```http
GET /api/v1/ratelimit/buckets
GET /api/v1/ratelimit/buckets?pattern=user:*&limit=100
```

#### Get Specific Bucket
```http
GET /api/v1/ratelimit/buckets/{key}
```

Response:
```json
{
  "key": "user:123",
  "bucket": {
    "allowed": true,
    "tokens_left": 45,
    "reset_time": "2024-01-15T15:35:00Z",
    "bucket_key": "user:123",
    "timestamp": "2024-01-15T15:30:00Z"
  }
}
```

#### Reset Bucket
```http
POST /api/v1/ratelimit/buckets/{key}/reset
```

#### Delete Bucket
```http
DELETE /api/v1/ratelimit/buckets/{key}
```

### Rate Limit Checking

#### Simple Rate Limit Check
```http
POST /api/v1/ratelimit/check
Content-Type: application/json

{
  "key": "user:123",
  "tokens": 1,
  "config_name": "default_user"
}
```

#### Multi-Layer Rate Limit Check
```http
POST /api/v1/ratelimit/check/multi
Content-Type: application/json

{
  "user_id": "user123",
  "org_id": "org456",
  "ip": "192.168.1.1",
  "endpoint": "/api/data",
  "method": "GET",
  "request_size": 1024,
  "metadata": {
    "tier": "premium"
  }
}
```

Response:
```json
{
  "request": {
    "user_id": "user123",
    "org_id": "org456",
    "ip": "192.168.1.1",
    "endpoint": "/api/data",
    "method": "GET",
    "request_size": 1024,
    "timestamp": "2024-01-15T15:30:00Z"
  },
  "result": {
    "allowed": true,
    "denied_by": "",
    "retry_after": 0,
    "layer_results": [
      {
        "allowed": true,
        "tokens_left": 95,
        "bucket_key": "user:user123",
        "config_used": "per_user:default_user"
      },
      {
        "allowed": true,
        "tokens_left": 450,
        "bucket_key": "ip:192.168.1.1",
        "config_used": "per_ip:default_ip"
      }
    ],
    "timestamp": "2024-01-15T15:30:00Z"
  }
}
```

### Statistics and Monitoring

#### Get Statistics
```http
GET /api/v1/ratelimit/stats
```

Response:
```json
{
  "stats": {
    "total_buckets": 1500,
    "active_buckets": 800,
    "total_requests": 50000,
    "allowed_requests": 48500,
    "denied_requests": 1500,
    "configs_by_type": {
      "default_user": 1,
      "default_ip": 1,
      "premium_user": 1
    },
    "last_updated": "2024-01-15T15:30:00Z"
  }
}
```

#### Cleanup Expired Buckets
```http
POST /api/v1/ratelimit/cleanup
```

### Testing

#### Test Rate Limiting
```http
POST /api/v1/ratelimit/test
Content-Type: application/json

{
  "user_id": "test_user",
  "ip": "127.0.0.1",
  "endpoint": "/api/test",
  "method": "GET",
  "metadata": {
    "tier": "premium"
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
    "github.com/dydoxy/proxy-engine-go/internal/security/ratelimit"
)

func main() {
    logger := logrus.New()
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })
    
    // Create token bucket manager
    storage := ratelimit.NewRedisBucketStorage(redisClient)
    manager := ratelimit.NewTokenBucketManager(storage, logger)
    defer manager.Close()
    
    // Create configuration
    config := &ratelimit.BucketConfig{
        Capacity:   100,
        RefillRate: 10,
    }
    
    ctx := context.Background()
    manager.SetConfig(ctx, "api_limit", config)
    
    // Check rate limit
    result, err := manager.CheckRateLimit(ctx, "user:123", 1, "api_limit")
    if err != nil {
        logger.Error(err)
        return
    }
    
    if !result.Allowed {
        logger.Warnf("Rate limit exceeded, retry after %d seconds", result.RetryAfter)
    }
}
```

### Multi-Layer Rate Limiting

```go
// Create multi-layer limiter
multiLayerLimiter := ratelimit.NewMultiLayerRateLimiter(manager, logger)

// Add strategies
multiLayerLimiter.AddStrategy(ratelimit.NewPerUserStrategy("user_config"))
multiLayerLimiter.AddStrategy(ratelimit.NewPerIPStrategy("ip_config"))
multiLayerLimiter.AddStrategy(ratelimit.NewPerOrgStrategy("org_config"))

// Check rate limit
request := &ratelimit.RateLimitRequest{
    UserID:   "user123",
    OrgID:    "org456",
    IP:       "192.168.1.1",
    Endpoint: "/api/data",
    Method:   "GET",
}

result, err := multiLayerLimiter.CheckRateLimit(ctx, request)
if err != nil {
    logger.Error(err)
    return
}

if !result.Allowed {
    logger.Warnf("Rate limit exceeded by %s layer", result.DeniedBy)
}
```

### Middleware Integration

```go
// Create middleware
middleware := ratelimit.NewRateLimitMiddleware(multiLayerLimiter, logger, nil)

// Use with Gin
r := gin.Default()
r.Use(middleware.GinMiddleware())

// Use with standard HTTP
http.Handle("/", middleware.HTTPMiddleware(yourHandler))
```

### Custom Strategy

```go
// Create custom strategy
type CustomStrategy struct {
    configName string
}

func (s *CustomStrategy) GetBucketKey(request *ratelimit.RateLimitRequest) string {
    return fmt.Sprintf("custom:%s:%s", request.UserID, request.Endpoint)
}

func (s *CustomStrategy) GetConfigName(request *ratelimit.RateLimitRequest) string {
    return s.configName
}

func (s *CustomStrategy) GetTokensRequired(request *ratelimit.RateLimitRequest) int64 {
    // Custom logic for token calculation
    if strings.Contains(request.Endpoint, "/expensive") {
        return 5 // Expensive endpoints cost more tokens
    }
    return 1
}

func (s *CustomStrategy) GetStrategyName() string {
    return "custom"
}

// Use custom strategy
customStrategy := &CustomStrategy{configName: "custom_config"}
multiLayerLimiter.AddStrategy(customStrategy)
```

## Performance Considerations

- **Memory Usage**: Buckets are cached in memory with automatic cleanup
- **Redis Efficiency**: Uses Redis pipelines for batch operations
- **Token Calculation**: O(1) time complexity for rate limit checks
- **Cleanup**: Automatic cleanup of expired buckets
- **Concurrency**: Thread-safe operations with minimal locking

## Monitoring & Alerting

The system provides comprehensive monitoring:

- **Request Statistics**: Total, allowed, denied requests
- **Bucket Metrics**: Active buckets, token consumption rates
- **Performance Metrics**: Response times, Redis operations
- **Error Tracking**: Failed operations and configuration errors
- **Capacity Planning**: Usage trends and growth patterns

## Configuration Examples

### API Gateway
```go
configs := map[string]*ratelimit.BucketConfig{
    "public_api": {
        Capacity:   1000,  // 1000 requests burst
        RefillRate: 100,   // 100 requests per second
    },
    "authenticated_api": {
        Capacity:   5000,  // 5000 requests burst
        RefillRate: 500,   // 500 requests per second
    },
    "premium_api": {
        Capacity:   10000, // 10000 requests burst
        RefillRate: 1000,  // 1000 requests per second
    },
}
```

### DDoS Protection
```go
ddosConfig := &ratelimit.BucketConfig{
    Capacity:   10,    // Very limited burst
    RefillRate: 1,     // 1 request per second
}
```

### File Upload
```go
uploadConfig := &ratelimit.BucketConfig{
    Capacity:   5,     // 5 uploads burst
    RefillRate: 1,     // 1 upload per second
}
```

## Future Enhancements

- **Adaptive Rate Limiting**: Dynamic adjustment based on system load
- **Machine Learning**: AI-powered anomaly detection
- **Geographic Limiting**: Location-based rate limiting
- **Time-based Rules**: Different limits for different time periods
- **Circuit Breaker**: Integration with circuit breaker patterns
- **Distributed Consensus**: Multi-region rate limiting coordination