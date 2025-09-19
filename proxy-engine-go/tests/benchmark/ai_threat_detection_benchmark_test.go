package benchmark

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
)

// BenchmarkAIThreatDetection benchmarks the AI threat detection system
func BenchmarkAIThreatDetection(b *testing.B) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})
	defer redisClient.Close()
	
	ctx := context.Background()
	redisClient.FlushDB(ctx)
	
	// Initialize AI components
	aiStorage := ai.NewRedisStorage(redisClient, logger)
	modelManager := ai.NewModelManager(aiStorage, logger)
	basicExtractor := ai.NewFeatureExtractor(logger)
	advancedExtractor := ai.NewAdvancedFeatureExtractor(logger)
	behavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)
	anomalyDetector := ai.NewAnomalyDetector(logger)
	threatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)
	adaptiveLearning := ai.NewAdaptiveLearningSystem(modelManager, aiStorage, logger)
	
	contentModel := ai.NewContentAnalysisModel(logger)
	modelManager.RegisterModel("content_analysis", contentModel)
	
	aiThreatDetector := ai.NewThreatDetector(&ai.ThreatDetectorConfig{
		Enabled:                    true,
		ContentAnalysisEnabled:     true,
		BehavioralAnalysisEnabled:  true,
		AnomalyDetectionEnabled:    true,
		ThreatIntelligenceEnabled:  true,
		AdaptiveLearningEnabled:    true,
		ConfidenceThreshold:        0.7,
		MaxProcessingTime:          5 * time.Second,
		EnableRealTimeUpdates:      true,
		ModelUpdateInterval:        24 * time.Hour,
	}, basicExtractor, advancedExtractor, behavioralAnalyzer, anomalyDetector,
		threatIntelligence, adaptiveLearning, modelManager, logger)
	
	// Test request
	testRequest := &ai.ContentRequest{
		URL:       "https://example.com/test",
		Method:    "GET",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		SourceIP:  "192.168.1.100",
		UserID:    "test_user",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
		},
		Timestamp: time.Now(),
	}
	
	b.ResetTimer()
	
	// Benchmark the threat detection
	b.Run("ThreatDetection", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := aiThreatDetector.AnalyzeRequest(ctx, testRequest)
			if err != nil {
				b.Fatalf("Threat detection failed: %v", err)
			}
		}
	})
}

// BenchmarkFeatureExtraction benchmarks feature extraction
func BenchmarkFeatureExtraction(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	basicExtractor := ai.NewFeatureExtractor(logger)
	advancedExtractor := ai.NewAdvancedFeatureExtractor(logger)
	
	testRequest := &ai.ContentRequest{
		URL:       "https://example.com/test?param1=value1&param2=value2",
		Method:    "GET",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		SourceIP:  "192.168.1.100",
		UserID:    "test_user",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
			"Referer":         "https://google.com/",
		},
		Timestamp: time.Now(),
	}
	
	b.Run("BasicFeatureExtraction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := basicExtractor.ExtractFeatures(testRequest)
			if err != nil {
				b.Fatalf("Basic feature extraction failed: %v", err)
			}
		}
	})
	
	b.Run("AdvancedFeatureExtraction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := advancedExtractor.ExtractFeatures(testRequest)
			if err != nil {
				b.Fatalf("Advanced feature extraction failed: %v", err)
			}
		}
	})
}

// BenchmarkBehavioralAnalysis benchmarks behavioral analysis
func BenchmarkBehavioralAnalysis(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15,
	})
	defer redisClient.Close()
	
	ctx := context.Background()
	redisClient.FlushDB(ctx)
	
	aiStorage := ai.NewRedisStorage(redisClient, logger)
	behavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)
	
	testRequest := &ai.ContentRequest{
		URL:       "https://example.com/test",
		Method:    "GET",
		UserAgent: "Mozilla/5.0",
		SourceIP:  "192.168.1.100",
		UserID:    "test_user",
		Timestamp: time.Now(),
	}
	
	b.ResetTimer()
	
	b.Run("BehavioralAnalysis", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := behavioralAnalyzer.AnalyzeBehavior(ctx, testRequest)\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Behavioral analysis failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkAnomalyDetection benchmarks anomaly detection\nfunc BenchmarkAnomalyDetection(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tanomalyDetector := ai.NewAnomalyDetector(logger)\n\t\n\t// Create sample behavioral data\n\tbehavioralData := &ai.BehavioralData{\n\t\tUserID:              \"test_user\",\n\t\tRequestsPerHour:     50,\n\t\tUniqueDomains:       10,\n\t\tSessionDuration:     1800,\n\t\tErrorRate:           0.02,\n\t\tUserAgentConsistency: 0.9,\n\t\tTimestamp:           time.Now(),\n\t}\n\t\n\tb.ResetTimer()\n\t\n\tb.Run(\"AnomalyDetection\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\t_, err := anomalyDetector.DetectAnomalies(behavioralData)\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Anomaly detection failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkContentAnalysisModel benchmarks the content analysis model\nfunc BenchmarkContentAnalysisModel(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tcontentModel := ai.NewContentAnalysisModel(logger)\n\t\n\t// Sample features\n\tfeatures := map[string]float64{\n\t\t\"url_length\":         42.0,\n\t\t\"domain_age\":         365.0,\n\t\t\"has_https\":          1.0,\n\t\t\"suspicious_keywords\": 0.0,\n\t\t\"entropy\":            3.5,\n\t\t\"request_size\":       1024.0,\n\t}\n\t\n\tb.ResetTimer()\n\t\n\tb.Run(\"ContentAnalysisModel\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\t_, err := contentModel.Predict(features)\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Content analysis model prediction failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkThreatIntelligence benchmarks threat intelligence lookups\nfunc BenchmarkThreatIntelligence(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tredisClient := redis.NewClient(&redis.Options{\n\t\tAddr: \"localhost:6379\",\n\t\tDB:   15,\n\t})\n\tdefer redisClient.Close()\n\t\n\tctx := context.Background()\n\tredisClient.FlushDB(ctx)\n\t\n\taiStorage := ai.NewRedisStorage(redisClient, logger)\n\tthreatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)\n\t\n\t// Add some test threat intelligence data\n\tredisClient.HSet(ctx, \"ai:threat_intel:domains:malware-example.com\",\n\t\t\"type\", \"malicious\",\n\t\t\"category\", \"malware\",\n\t\t\"confidence\", 0.9)\n\t\n\tredisClient.SAdd(ctx, \"ai:threat_intel:domains:set\", \"malware-example.com\")\n\t\n\tb.ResetTimer()\n\t\n\tb.Run(\"DomainLookup\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\t_, err := threatIntelligence.CheckDomain(ctx, \"malware-example.com\")\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Domain lookup failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n\t\n\tb.Run(\"IPLookup\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\t_, err := threatIntelligence.CheckIP(ctx, \"192.168.1.100\")\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"IP lookup failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkRedisStorage benchmarks Redis storage operations\nfunc BenchmarkRedisStorage(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tredisClient := redis.NewClient(&redis.Options{\n\t\tAddr: \"localhost:6379\",\n\t\tDB:   15,\n\t})\n\tdefer redisClient.Close()\n\t\n\tctx := context.Background()\n\tredisClient.FlushDB(ctx)\n\t\n\taiStorage := ai.NewRedisStorage(redisClient, logger)\n\t\n\ttestData := map[string]interface{}{\n\t\t\"key1\": \"value1\",\n\t\t\"key2\": 42,\n\t\t\"key3\": 3.14,\n\t\t\"key4\": true,\n\t}\n\t\n\tb.Run(\"StoreData\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tkey := fmt.Sprintf(\"test:data:%d\", i)\n\t\t\terr := aiStorage.StoreData(ctx, key, testData, time.Hour)\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Store data failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n\t\n\tb.Run(\"RetrieveData\", func(b *testing.B) {\n\t\t// Pre-populate some data\n\t\tfor i := 0; i < 100; i++ {\n\t\t\tkey := fmt.Sprintf(\"test:retrieve:%d\", i)\n\t\t\taiStorage.StoreData(ctx, key, testData, time.Hour)\n\t\t}\n\t\t\n\t\tb.ResetTimer()\n\t\t\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tkey := fmt.Sprintf(\"test:retrieve:%d\", i%100)\n\t\t\t_, err := aiStorage.RetrieveData(ctx, key)\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Retrieve data failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkMetricsCollection benchmarks metrics collection\nfunc BenchmarkMetricsCollection(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tmetricsCollector := ai.NewMetricsCollector(logger)\n\t\n\tlabels := map[string]string{\n\t\t\"component\": \"benchmark\",\n\t\t\"test\":      \"metrics\",\n\t}\n\t\n\tb.Run(\"IncrementCounter\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tmetricsCollector.IncrementCounter(\"benchmark_counter\", labels)\n\t\t}\n\t})\n\t\n\tb.Run(\"SetGauge\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tmetricsCollector.SetGauge(\"benchmark_gauge\", float64(i), labels)\n\t\t}\n\t})\n\t\n\tb.Run(\"ObserveHistogram\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tmetricsCollector.ObserveHistogram(\"benchmark_histogram\", float64(i%100), labels)\n\t\t}\n\t})\n\t\n\tb.Run(\"RecordTimer\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tduration := time.Duration(i%1000) * time.Millisecond\n\t\t\tmetricsCollector.RecordTimer(\"benchmark_timer\", duration, labels)\n\t\t}\n\t})\n}\n\n// BenchmarkConcurrentThreatDetection benchmarks concurrent threat detection\nfunc BenchmarkConcurrentThreatDetection(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tredisClient := redis.NewClient(&redis.Options{\n\t\tAddr: \"localhost:6379\",\n\t\tDB:   15,\n\t})\n\tdefer redisClient.Close()\n\t\n\tctx := context.Background()\n\tredisClient.FlushDB(ctx)\n\t\n\t// Initialize AI components\n\taiStorage := ai.NewRedisStorage(redisClient, logger)\n\tmodelManager := ai.NewModelManager(aiStorage, logger)\n\tbasicExtractor := ai.NewFeatureExtractor(logger)\n\tadvancedExtractor := ai.NewAdvancedFeatureExtractor(logger)\n\tbehavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)\n\tanomalyDetector := ai.NewAnomalyDetector(logger)\n\tthreatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)\n\tadaptiveLearning := ai.NewAdaptiveLearningSystem(modelManager, aiStorage, logger)\n\t\n\tcontentModel := ai.NewContentAnalysisModel(logger)\n\tmodelManager.RegisterModel(\"content_analysis\", contentModel)\n\t\n\taiThreatDetector := ai.NewThreatDetector(&ai.ThreatDetectorConfig{\n\t\tEnabled:                    true,\n\t\tContentAnalysisEnabled:     true,\n\t\tBehavioralAnalysisEnabled:  true,\n\t\tAnomalyDetectionEnabled:    true,\n\t\tThreatIntelligenceEnabled:  true,\n\t\tAdaptiveLearningEnabled:    true,\n\t\tConfidenceThreshold:        0.7,\n\t\tMaxProcessingTime:          5 * time.Second,\n\t\tEnableRealTimeUpdates:      true,\n\t\tModelUpdateInterval:        24 * time.Hour,\n\t}, basicExtractor, advancedExtractor, behavioralAnalyzer, anomalyDetector,\n\t\tthreatIntelligence, adaptiveLearning, modelManager, logger)\n\t\n\tb.Run(\"ConcurrentThreatDetection\", func(b *testing.B) {\n\t\tb.RunParallel(func(pb *testing.PB) {\n\t\t\ti := 0\n\t\t\tfor pb.Next() {\n\t\t\t\ttestRequest := &ai.ContentRequest{\n\t\t\t\t\tURL:       fmt.Sprintf(\"https://example.com/test/%d\", i),\n\t\t\t\t\tMethod:    \"GET\",\n\t\t\t\t\tUserAgent: \"Mozilla/5.0\",\n\t\t\t\t\tSourceIP:  fmt.Sprintf(\"192.168.1.%d\", 100+(i%50)),\n\t\t\t\t\tUserID:    fmt.Sprintf(\"user_%d\", i%10),\n\t\t\t\t\tTimestamp: time.Now(),\n\t\t\t\t}\n\t\t\t\t\n\t\t\t\t_, err := aiThreatDetector.AnalyzeRequest(ctx, testRequest)\n\t\t\t\tif err != nil {\n\t\t\t\t\tb.Fatalf(\"Concurrent threat detection failed: %v\", err)\n\t\t\t\t}\n\t\t\t\t\n\t\t\t\ti++\n\t\t\t}\n\t\t})\n\t})\n}\n\n// BenchmarkMemoryUsage benchmarks memory usage of AI components\nfunc BenchmarkMemoryUsage(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tredisClient := redis.NewClient(&redis.Options{\n\t\tAddr: \"localhost:6379\",\n\t\tDB:   15,\n\t})\n\tdefer redisClient.Close()\n\t\n\tctx := context.Background()\n\tredisClient.FlushDB(ctx)\n\t\n\t// Initialize AI components\n\taiStorage := ai.NewRedisStorage(redisClient, logger)\n\tmodelManager := ai.NewModelManager(aiStorage, logger)\n\tbasicExtractor := ai.NewFeatureExtractor(logger)\n\tadvancedExtractor := ai.NewAdvancedFeatureExtractor(logger)\n\tbehavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)\n\tanomalyDetector := ai.NewAnomalyDetector(logger)\n\tthreatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)\n\tadaptiveLearning := ai.NewAdaptiveLearningSystem(modelManager, aiStorage, logger)\n\t\n\tcontentModel := ai.NewContentAnalysisModel(logger)\n\tmodelManager.RegisterModel(\"content_analysis\", contentModel)\n\t\n\taiThreatDetector := ai.NewThreatDetector(&ai.ThreatDetectorConfig{\n\t\tEnabled:                    true,\n\t\tContentAnalysisEnabled:     true,\n\t\tBehavioralAnalysisEnabled:  true,\n\t\tAnomalyDetectionEnabled:    true,\n\t\tThreatIntelligenceEnabled:  true,\n\t\tAdaptiveLearningEnabled:    true,\n\t\tConfidenceThreshold:        0.7,\n\t\tMaxProcessingTime:          5 * time.Second,\n\t\tEnableRealTimeUpdates:      true,\n\t\tModelUpdateInterval:        24 * time.Hour,\n\t}, basicExtractor, advancedExtractor, behavioralAnalyzer, anomalyDetector,\n\t\tthreatIntelligence, adaptiveLearning, modelManager, logger)\n\t\n\tb.Run(\"MemoryUsage\", func(b *testing.B) {\n\t\trequests := make([]*ai.ContentRequest, b.N)\n\t\t\n\t\t// Pre-generate requests to avoid allocation during benchmark\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\trequests[i] = &ai.ContentRequest{\n\t\t\t\tURL:       fmt.Sprintf(\"https://example.com/test/%d\", i),\n\t\t\t\tMethod:    \"GET\",\n\t\t\t\tUserAgent: \"Mozilla/5.0\",\n\t\t\t\tSourceIP:  fmt.Sprintf(\"192.168.1.%d\", 100+(i%50)),\n\t\t\t\tUserID:    fmt.Sprintf(\"user_%d\", i%10),\n\t\t\t\tTimestamp: time.Now(),\n\t\t\t}\n\t\t}\n\t\t\n\t\tb.ResetTimer()\n\t\t\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\t_, err := aiThreatDetector.AnalyzeRequest(ctx, requests[i])\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Memory usage benchmark failed: %v\", err)\n\t\t\t}\n\t\t}\n\t})\n}\n\n// BenchmarkLatency benchmarks latency of different AI components\nfunc BenchmarkLatency(b *testing.B) {\n\tlogger := logrus.New()\n\tlogger.SetLevel(logrus.WarnLevel)\n\t\n\tredisClient := redis.NewClient(&redis.Options{\n\t\tAddr: \"localhost:6379\",\n\t\tDB:   15,\n\t})\n\tdefer redisClient.Close()\n\t\n\tctx := context.Background()\n\tredisClient.FlushDB(ctx)\n\t\n\t// Initialize components\n\taiStorage := ai.NewRedisStorage(redisClient, logger)\n\tbasicExtractor := ai.NewFeatureExtractor(logger)\n\tbehavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)\n\tanomalyDetector := ai.NewAnomalyDetector(logger)\n\tthreatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)\n\t\n\ttestRequest := &ai.ContentRequest{\n\t\tURL:       \"https://example.com/test\",\n\t\tMethod:    \"GET\",\n\t\tUserAgent: \"Mozilla/5.0\",\n\t\tSourceIP:  \"192.168.1.100\",\n\t\tUserID:    \"test_user\",\n\t\tTimestamp: time.Now(),\n\t}\n\t\n\tb.Run(\"FeatureExtractionLatency\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tstart := time.Now()\n\t\t\t_, err := basicExtractor.ExtractFeatures(testRequest)\n\t\t\tlatency := time.Since(start)\n\t\t\t\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Feature extraction failed: %v\", err)\n\t\t\t}\n\t\t\t\n\t\t\t// Log latency for analysis\n\t\t\tif i%1000 == 0 {\n\t\t\t\tb.Logf(\"Feature extraction latency: %v\", latency)\n\t\t\t}\n\t\t}\n\t})\n\t\n\tb.Run(\"BehavioralAnalysisLatency\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tstart := time.Now()\n\t\t\t_, err := behavioralAnalyzer.AnalyzeBehavior(ctx, testRequest)\n\t\t\tlatency := time.Since(start)\n\t\t\t\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Behavioral analysis failed: %v\", err)\n\t\t\t}\n\t\t\t\n\t\t\tif i%1000 == 0 {\n\t\t\t\tb.Logf(\"Behavioral analysis latency: %v\", latency)\n\t\t\t}\n\t\t}\n\t})\n\t\n\tb.Run(\"ThreatIntelligenceLatency\", func(b *testing.B) {\n\t\tfor i := 0; i < b.N; i++ {\n\t\t\tstart := time.Now()\n\t\t\t_, err := threatIntelligence.CheckDomain(ctx, \"example.com\")\n\t\t\tlatency := time.Since(start)\n\t\t\t\n\t\t\tif err != nil {\n\t\t\t\tb.Fatalf(\"Threat intelligence lookup failed: %v\", err)\n\t\t\t}\n\t\t\t\n\t\t\tif i%1000 == 0 {\n\t\t\t\tb.Logf(\"Threat intelligence latency: %v\", latency)\n\t\t\t}\n\t\t}\n\t})\n}"