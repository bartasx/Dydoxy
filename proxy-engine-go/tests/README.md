# AI Threat Detection System Tests

This directory contains comprehensive tests for the AI Threat Detection System, including unit tests, integration tests, end-to-end tests, and benchmarks.

## Test Structure

```
tests/
├── e2e/                    # End-to-end tests
├── benchmark/              # Performance benchmarks
└── README.md              # This file
```

## Test Categories

### 1. Unit Tests
Unit tests are located alongside the source code in each package (e.g., `internal/security/ai/*_test.go`).

**Coverage includes:**
- Feature extraction algorithms
- ML model implementations
- Behavioral analysis logic
- Anomaly detection algorithms
- Threat intelligence services
- Storage operations
- Metrics collection
- Alert management

### 2. Integration Tests
Integration tests verify that components work together correctly.

**Coverage includes:**
- AI-enhanced content filtering
- Adaptive rate limiting
- Model management
- Redis storage integration
- API endpoints
- WebSocket communication

### 3. End-to-End Tests (`tests/e2e/`)
End-to-end tests simulate real-world scenarios and verify the complete system behavior.

**Test scenarios:**
- Complete request processing pipeline
- Threat detection accuracy
- System performance under load
- Concurrent request handling
- Error handling and resilience
- API functionality
- Real-time monitoring

### 4. Benchmark Tests (`tests/benchmark/`)
Performance benchmarks measure system performance and identify bottlenecks.

**Benchmarks include:**
- Threat detection latency
- Feature extraction performance
- Model prediction speed
- Storage operation performance
- Concurrent processing capability
- Memory usage patterns

## Running Tests

### Prerequisites

1. **Redis Server**: Tests require a running Redis instance
   ```bash
   # Using Docker
   docker run -d --name redis-test -p 6379:6379 redis:7-alpine
   
   # Or using system Redis
   redis-server
   ```

2. **Go Dependencies**: Install test dependencies
   ```bash
   go mod download
   go install github.com/stretchr/testify
   ```

### Unit Tests

Run all unit tests:
```bash
# Run all unit tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run tests for specific package
go test ./internal/security/ai/

# Run specific test
go test -run TestThreatDetector ./internal/security/ai/
```

### Integration Tests

Integration tests are included in the unit test suite but can be run separately:
```bash
# Run integration tests (requires Redis)
go test -tags=integration ./...

# Run with verbose output
go test -v -tags=integration ./internal/security/ai/
```

### End-to-End Tests

Run end-to-end tests:
```bash
# Run E2E tests (requires Redis)
go test -v ./tests/e2e/

# Run specific E2E test
go test -run TestBenignRequest ./tests/e2e/

# Run E2E tests with timeout
go test -timeout 30m ./tests/e2e/
```

### Benchmark Tests

Run performance benchmarks:
```bash
# Run all benchmarks
go test -bench=. ./tests/benchmark/

# Run specific benchmark
go test -bench=BenchmarkThreatDetection ./tests/benchmark/

# Run benchmarks with memory profiling
go test -bench=. -benchmem ./tests/benchmark/

# Run benchmarks multiple times for accuracy
go test -bench=. -count=5 ./tests/benchmark/

# Generate CPU profile
go test -bench=BenchmarkThreatDetection -cpuprofile=cpu.prof ./tests/benchmark/

# Generate memory profile
go test -bench=BenchmarkThreatDetection -memprofile=mem.prof ./tests/benchmark/
```

## Test Configuration

### Environment Variables

Tests can be configured using environment variables:

```bash
# Redis configuration
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_DB=15  # Use separate DB for tests

# Test configuration
export TEST_TIMEOUT=30m
export TEST_VERBOSE=true
export TEST_PARALLEL=4

# AI system configuration for tests
export AI_THREAT_DETECTION_ENABLED=true
export AI_CONFIDENCE_THRESHOLD=0.7
export AI_MAX_PROCESSING_TIME_SECONDS=5
```

### Test Data

Tests use predefined test data and scenarios:

- **Benign requests**: Normal user behavior patterns
- **Malicious requests**: Known attack patterns
- **Anomalous behavior**: Statistical outliers
- **Threat intelligence**: Sample malicious domains and IPs

## Test Scenarios

### End-to-End Test Scenarios

1. **Normal Request Flow**
   - Benign requests pass through without issues
   - Proper headers and metrics are set
   - Performance meets requirements

2. **Threat Detection**
   - Malicious domains are blocked
   - Suspicious patterns are flagged
   - Threat scores are calculated correctly

3. **Behavioral Analysis**
   - Normal user behavior is learned
   - Anomalous patterns are detected
   - Adaptive thresholds work correctly

4. **Rate Limiting**
   - AI-enhanced rate limiting adapts to threats
   - Bot behavior triggers stricter limits
   - Legitimate users are not affected

5. **System Resilience**
   - Handles edge cases gracefully
   - Recovers from component failures
   - Maintains performance under load

### Performance Benchmarks

1. **Latency Benchmarks**
   - Feature extraction: < 1ms
   - Threat detection: < 10ms
   - Model prediction: < 5ms
   - Storage operations: < 2ms

2. **Throughput Benchmarks**
   - Requests per second: > 1000
   - Concurrent users: > 100
   - Memory usage: < 100MB baseline

3. **Scalability Benchmarks**
   - Linear scaling with CPU cores
   - Efficient memory usage
   - Minimal garbage collection impact

## Test Data and Fixtures

### Sample Threat Intelligence

```json
{
  "malicious_domains": [
    "malware-example.com",
    "phishing-site.net",
    "dangerous-domain.org"
  ],
  "malicious_ips": [
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1"
  ],
  "suspicious_user_agents": [
    "wget/1.20.3",
    "curl/7.68.0",
    "bot/1.0"
  ]
}
```

### Behavioral Profiles

```json
{
  "normal_user": {
    "requests_per_hour": 50,
    "unique_domains": 10,
    "session_duration": 1800,
    "error_rate": 0.02
  },
  "power_user": {
    "requests_per_hour": 200,
    "unique_domains": 50,
    "session_duration": 3600,
    "error_rate": 0.01
  },
  "bot": {
    "requests_per_hour": 1000,
    "unique_domains": 5,
    "session_duration": 60,
    "error_rate": 0.1
  }
}
```

## Continuous Integration

### GitHub Actions

Example CI configuration:

```yaml
name: AI Threat Detection Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Install dependencies
      run: go mod download
    
    - name: Run unit tests
      run: go test -v -cover ./...
    
    - name: Run integration tests
      run: go test -v -tags=integration ./...
    
    - name: Run E2E tests
      run: go test -v ./tests/e2e/
      env:
        REDIS_HOST: localhost
        REDIS_PORT: 6379
        REDIS_DB: 15
    
    - name: Run benchmarks
      run: go test -bench=. -benchtime=10s ./tests/benchmark/
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
```

## Test Metrics and Reporting

### Coverage Requirements

- **Unit tests**: > 90% code coverage
- **Integration tests**: > 80% feature coverage
- **E2E tests**: > 95% user scenario coverage

### Performance Requirements

- **Latency**: 95th percentile < 50ms
- **Throughput**: > 1000 requests/second
- **Memory**: < 200MB under normal load
- **CPU**: < 50% utilization under normal load

### Quality Gates

Tests must pass the following quality gates:

1. **Functionality**: All tests pass
2. **Performance**: Benchmarks meet requirements
3. **Coverage**: Minimum coverage thresholds met
4. **Security**: No security vulnerabilities detected
5. **Reliability**: Tests are stable and repeatable

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```bash
   # Check Redis status
   redis-cli ping
   
   # Start Redis if needed
   redis-server
   ```

2. **Test Timeouts**
   ```bash
   # Increase timeout
   go test -timeout 60m ./tests/e2e/
   ```

3. **Memory Issues**
   ```bash
   # Run with memory profiling
   go test -memprofile=mem.prof ./tests/benchmark/
   go tool pprof mem.prof
   ```

4. **Race Conditions**
   ```bash
   # Run with race detector
   go test -race ./...
   ```

### Debugging Tests

1. **Verbose Output**
   ```bash
   go test -v ./...
   ```

2. **Specific Test**
   ```bash
   go test -run TestSpecificFunction ./package/
   ```

3. **Debug Logging**
   ```bash
   export LOG_LEVEL=debug
   go test -v ./...
   ```

4. **Profiling**
   ```bash
   go test -cpuprofile=cpu.prof -memprofile=mem.prof ./...
   go tool pprof cpu.prof
   ```

## Contributing

When adding new tests:

1. **Follow naming conventions**: `Test*` for tests, `Benchmark*` for benchmarks
2. **Use table-driven tests** for multiple scenarios
3. **Mock external dependencies** appropriately
4. **Include both positive and negative test cases**
5. **Add performance benchmarks** for critical paths
6. **Document test scenarios** and expected outcomes
7. **Ensure tests are deterministic** and repeatable

### Test Template

```go
func TestNewFeature(t *testing.T) {
    // Setup
    logger := logrus.New()
    logger.SetLevel(logrus.WarnLevel)
    
    // Test cases
    tests := []struct {
        name     string
        input    interface{}
        expected interface{}
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    validInput,
            expected: expectedOutput,
            wantErr:  false,
        },
        {
            name:     "invalid input",
            input:    invalidInput,
            expected: nil,
            wantErr:  true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
            result, err := functionUnderTest(tt.input)
            
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```