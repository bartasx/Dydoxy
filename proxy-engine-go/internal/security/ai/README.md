# AI Threat Detection Module

This module provides AI-powered threat detection capabilities for the Dydoxy proxy management system. It enhances the existing security infrastructure with machine learning models, behavioral analysis, and advanced threat intelligence.

## Overview

The AI threat detection system analyzes network traffic in real-time to identify sophisticated threats that traditional signature-based systems might miss. It integrates seamlessly with the existing content filtering, rate limiting, and DDoS protection modules.

## Architecture

### Core Components

- **AIThreatDetector**: Main orchestration component for threat analysis
- **MLModel**: Machine learning model interface and implementations
- **FeatureExtractor**: Converts requests to feature vectors for ML analysis
- **BehavioralAnalyzer**: Analyzes user and IP behavior patterns
- **ModelManager**: Manages ML model lifecycle and versioning
- **ThreatIntelligenceService**: Provides external threat intelligence integration

### Integration Points

- **Content Filter Enhancement**: Adds AI analysis to existing content filtering
- **Adaptive Rate Limiting**: Adjusts rate limits based on threat analysis
- **Real-time Monitoring**: Provides WebSocket events for dashboard integration
- **Audit and Compliance**: Comprehensive logging and reporting

## Features

### Machine Learning Models

1. **Content Analysis Model**: Analyzes request content for malicious patterns
2. **Behavioral Analysis Model**: Detects anomalous user/IP behavior
3. **Network Pattern Model**: Identifies network-level attack patterns
4. **Zero-Day Detection Model**: Detects previously unknown threats

### Feature Engineering

The system extracts comprehensive features from each request:

- **URL Features**: Length, entropy, domain age, subdomain count
- **Content Features**: Headers, content type, body analysis
- **Behavioral Features**: Request patterns, timing, frequency
- **Network Features**: IP reputation, geolocation, ASN analysis
- **Historical Features**: Previous violations, account age, trust score

### Threat Detection Capabilities

- **Real-time Analysis**: <50ms processing time for production traffic
- **Adaptive Learning**: Continuous model improvement with feedback
- **Multi-layered Detection**: Combines multiple analysis techniques
- **Configurable Policies**: Per-organization threat detection policies
- **Comprehensive Reporting**: Detailed audit trails and compliance reports

## Usage

### Basic Integration

```go
// Initialize AI threat detector
detector := ai.NewThreatDetector(storage, logger)

// Analyze a request
request := &ai.ThreatAnalysisRequest{
    RequestID: "req-123",
    SourceIP:  net.ParseIP("192.168.1.1"),
    URL:       "https://example.com/suspicious/path",
    Method:    "GET",
    Headers:   headers,
    Timestamp: time.Now(),
}

result, err := detector.AnalyzeRequest(ctx, request)
if err != nil {
    log.Errorf("Threat analysis failed: %v", err)
    return
}

if result.IsThreat {
    log.Warnf("Threat detected: %s (confidence: %.2f)", 
        result.ThreatType, result.Confidence)
    // Take appropriate action based on result.RecommendedAction
}
```

### Feature Extraction

```go
// Extract features from a request
extractor := ai.NewDefaultFeatureExtractor(logger)
features, err := extractor.ExtractFeatures(ctx, request)
if err != nil {
    return err
}

// Use features for ML model inference
prediction, err := model.Predict(ctx, features.ToMap())
```

### Behavioral Analysis

```go
// Analyze user behavior
analyzer := ai.NewBehavioralAnalyzer(storage, logger)
analysis, err := analyzer.AnalyzeBehavior(ctx, "user123", requestContext)
if err != nil {
    return err
}

if analysis.IsAnomalous {
    log.Warnf("Anomalous behavior detected for user %s: %v", 
        "user123", analysis.AnomalyReasons)
}
```

## Configuration

### Threat Detection Policies

```go
policies := &ai.ThreatPolicies{
    GlobalEnabled:        true,
    ConfidenceThreshold:  0.8,
    ThreatLevelThresholds: map[ai.ThreatLevel]float64{
        ai.ThreatLevelLow:      0.3,
        ai.ThreatLevelMedium:   0.6,
        ai.ThreatLevelHigh:     0.8,
        ai.ThreatLevelCritical: 0.95,
    },
    ActionPolicies: map[ai.ThreatType]ai.ActionType{
        ai.ThreatTypeMalware:  ai.ActionBlock,
        ai.ThreatTypePhishing: ai.ActionBlock,
        ai.ThreatTypeSuspicious: ai.ActionMonitor,
    },
    BehavioralAnalysis:   true,
    MachineLearning:      true,
    ThreatIntelligence:   true,
    AlertingEnabled:      true,
    AlertThreshold:       ai.ThreatLevelMedium,
}

err := detector.ConfigurePolicies(ctx, policies)
```

## Performance Considerations

### Optimization Strategies

1. **Model Optimization**: Quantized models for faster inference
2. **Feature Caching**: Redis caching for computed features
3. **Async Processing**: Non-blocking analysis for high throughput
4. **Circuit Breakers**: Graceful degradation when models are unavailable

### Monitoring Metrics

- **Latency**: Average processing time per request
- **Throughput**: Requests processed per second
- **Accuracy**: Model precision, recall, and F1 scores
- **Error Rate**: Failed analysis attempts

## Testing

### Unit Tests

```bash
cd proxy-engine-go/internal/security/ai
go test -v ./...
```

### Integration Tests

```bash
go test -v -tags=integration ./...
```

### Performance Tests

```bash
go test -v -bench=. ./...
```

## Development

### Adding New Models

1. Implement the `MLModel` interface
2. Add model registration in `ModelManager`
3. Create training data structures
4. Add comprehensive tests

### Adding New Features

1. Extend `FeatureExtractor` interface
2. Update feature extraction logic
3. Add feature validation
4. Update tests and documentation

## Security Considerations

- **Model Security**: Protection against adversarial attacks
- **Data Privacy**: Secure handling of request data
- **Access Control**: Proper authentication for management APIs
- **Audit Logging**: Comprehensive security event logging

## Dependencies

- **Redis**: Model caching and behavioral profiles
- **Logrus**: Structured logging
- **Context**: Request context and cancellation
- **Net**: IP address handling and network analysis

## Future Enhancements

- **Federated Learning**: Collaborative model training
- **Advanced ML Models**: Deep learning and transformer models
- **Real-time Retraining**: Continuous model updates
- **Multi-modal Analysis**: Image and document analysis
- **Graph Analysis**: Network relationship analysis