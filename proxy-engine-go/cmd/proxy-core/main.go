package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"github.com/dydoxy/proxy-engine-go/internal/common/config"
	"github.com/dydoxy/proxy-engine-go/internal/common/logging"
	"github.com/dydoxy/proxy-engine-go/internal/proxy/socks5"
	"github.com/dydoxy/proxy-engine-go/internal/proxy/http"
	"github.com/dydoxy/proxy-engine-go/internal/security/filter"
	"github.com/dydoxy/proxy-engine-go/internal/security/ratelimit"
	"github.com/dydoxy/proxy-engine-go/internal/security/ai"
)

func main() {
	// Initialize configuration
	cfg := config.Load()
	
	// Initialize logging
	logger := logging.NewLogger(cfg.LogLevel)
	
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	
	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	
	// Initialize AI threat detection system
	aiStorage := ai.NewRedisStorage(redisClient, logger)
	
	// Initialize AI models
	modelManager := ai.NewModelManager(aiStorage, logger)
	
	// Initialize feature extractors
	basicExtractor := ai.NewFeatureExtractor(logger)
	advancedExtractor := ai.NewAdvancedFeatureExtractor(logger)
	
	// Initialize behavioral analyzer
	behavioralAnalyzer := ai.NewBehavioralAnalyzer(aiStorage, logger)
	
	// Initialize anomaly detector
	anomalyDetector := ai.NewAnomalyDetector(logger)
	
	// Initialize content analysis model
	contentModel := ai.NewContentAnalysisModel(logger)
	if err := modelManager.RegisterModel("content_analysis", contentModel); err != nil {
		logger.Warnf("Failed to register content analysis model: %v", err)
	}
	
	// Initialize threat intelligence service
	threatIntelligence := ai.NewThreatIntelligenceService(aiStorage, logger)
	
	// Initialize adaptive learning system
	adaptiveLearning := ai.NewAdaptiveLearningSystem(modelManager, aiStorage, logger)
	
	// Initialize main AI threat detector
	aiThreatDetector := ai.NewThreatDetector(&ai.ThreatDetectorConfig{
		Enabled:                    cfg.AIThreatDetection.Enabled,
		ContentAnalysisEnabled:     cfg.AIThreatDetection.ContentAnalysisEnabled,
		BehavioralAnalysisEnabled:  cfg.AIThreatDetection.BehavioralAnalysisEnabled,
		AnomalyDetectionEnabled:    cfg.AIThreatDetection.AnomalyDetectionEnabled,
		ThreatIntelligenceEnabled:  cfg.AIThreatDetection.ThreatIntelligenceEnabled,
		AdaptiveLearningEnabled:    cfg.AIThreatDetection.AdaptiveLearningEnabled,
		ConfidenceThreshold:        cfg.AIThreatDetection.ConfidenceThreshold,
		MaxProcessingTime:          time.Duration(cfg.AIThreatDetection.MaxProcessingTimeSeconds) * time.Second,
		EnableRealTimeUpdates:      cfg.AIThreatDetection.EnableRealTimeUpdates,
		ModelUpdateInterval:        time.Duration(cfg.AIThreatDetection.ModelUpdateIntervalHours) * time.Hour,
	}, basicExtractor, advancedExtractor, behavioralAnalyzer, anomalyDetector, 
	   threatIntelligence, adaptiveLearning, modelManager, logger)
	
	// Initialize AI-enhanced content filter
	aiEnhancedFilter := ai.NewAIEnhancedContentFilter(contentFilter, aiThreatDetector, logger)
	
	// Initialize adaptive rate limiter
	aiAdaptiveRateLimiter := ai.NewAIAdaptiveRateLimiter(multiLayerLimiter, aiThreatDetector, logger)
	
	// Initialize metrics collector
	var metricsCollector *ai.MetricsCollector
	if cfg.AIThreatDetection.MetricsEnabled {
		metricsCollector = ai.NewMetricsCollector(logger)
	}
	
	// Initialize health monitor
	healthMonitor := ai.NewHealthMonitor(&ai.HealthMonitorConfig{
		Enabled:         true,
		CheckInterval:   30 * time.Second,
		AlertThreshold:  0.8,
		EnableAlerting:  cfg.AIThreatDetection.AlertingEnabled,
	}, logger)
	
	// Initialize alert manager
	var alertManager *ai.AlertManager
	if cfg.AIThreatDetection.AlertingEnabled {
		alertManager = ai.NewAlertManager(ai.GetDefaultAlertManagerConfig(), logger)
	}
	
	// Initialize WebSocket hub for real-time monitoring
	wsHub := ai.NewWebSocketHub(logger)
	
	// Start AI system components
	if cfg.AIThreatDetectionEnabled {
		// Start metrics collection
		if metricsCollector != nil {
			go metricsCollector.Start(ctx)
		}
		
		// Start health monitoring
		go healthMonitor.Start(ctx)
		
		// Start alert manager
		if alertManager != nil {
			if err := alertManager.Start(); err != nil {
				logger.Warnf("Failed to start alert manager: %v", err)
			}
		}
		
		// Start WebSocket hub
		go wsHub.Start()
		
		// Start adaptive learning
		go adaptiveLearning.Start(ctx)
		
		// Start threat intelligence updates
		go threatIntelligence.StartPeriodicUpdates(ctx)
		
		logger.Info("AI threat detection system initialized and started")
	} else {
		logger.Info("AI threat detection system is disabled")
	}
	
	// Initialize content filtering
	filterStorage := filter.NewRedisStorage(redisClient)
	
	// Initialize list management
	listStorage := filter.NewRedisListStorage(redisClient)
	listManager := filter.NewManager(listStorage, logger)
	
	// Register threat feed providers
	malwareFeed := filter.NewMalwareDomainsThreatFeed(logger)
	phishingFeed := filter.NewPhishingDomainsThreatFeed(logger)
	listManager.RegisterThreatFeedProvider(malwareFeed)
	listManager.RegisterThreatFeedProvider(phishingFeed)
	
	// Initialize content filter with lists
	contentFilter := filter.NewEngineWithLists(filterStorage, listManager, logger)
	
	// Initialize rate limiting
	bucketStorage := ratelimit.NewRedisBucketStorage(redisClient)
	bucketManager := ratelimit.NewTokenBucketManager(bucketStorage, logger)
	
	// Initialize user/org limit management
	userOrgStorage := ratelimit.NewRedisUserOrgLimitStorage(redisClient)
	userOrgManager := ratelimit.NewUserOrgLimitManager(userOrgStorage, bucketManager, logger)
	
	// Create default rate limit configurations
	if err := createDefaultRateLimitConfigs(ctx, bucketManager, logger); err != nil {
		logger.Warnf("Failed to create default rate limit configs: %v", err)
	}
	
	// Create default user/org limits
	if err := createDefaultUserOrgLimits(ctx, userOrgManager, logger); err != nil {
		logger.Warnf("Failed to create default user/org limits: %v", err)
	}
	
	// Initialize multi-layer rate limiter
	multiLayerLimiter := ratelimit.NewMultiLayerRateLimiter(bucketManager, logger)
	
	// Add rate limiting strategies
	multiLayerLimiter.AddStrategy(ratelimit.NewPerUserStrategy("default_user"))
	multiLayerLimiter.AddStrategy(ratelimit.NewPerIPStrategy("default_ip"))
	multiLayerLimiter.AddStrategy(ratelimit.NewPerOrgStrategy("default_org"))
	
	// Add user/org aware strategies
	multiLayerLimiter.AddStrategy(ratelimit.NewUserOrgAwareStrategy(userOrgManager, ratelimit.LimitTypeRequestsPerHour))
	multiLayerLimiter.AddStrategy(ratelimit.NewHierarchicalStrategy(userOrgManager, ratelimit.LimitTypeRequestsPerDay))
	
	// Load existing rules
	if err := contentFilter.ReloadRules(ctx); err != nil {
		logger.Warnf("Failed to load existing rules: %v", err)
	}
	
	// Create default rules if none exist
	if err := createDefaultRules(ctx, contentFilter, logger); err != nil {
		logger.Warnf("Failed to create default rules: %v", err)
	}
	
	// Create default blacklist entries
	if err := createDefaultBlacklist(ctx, listManager, logger); err != nil {
		logger.Warnf("Failed to create default blacklist: %v", err)
	}
	
	// Initialize services
	socks5Server := socks5.NewServer(cfg.SOCKS5Port, logger)
	httpProxy := http.NewProxy(cfg.HTTPPort, logger)
	
	// Setup HTTP API
	r := gin.Default()
	
	// Add AI security middleware (if enabled)
	if cfg.AIThreatDetectionEnabled {
		aiSecurityMiddleware := ai.NewAISecurityMiddleware(aiThreatDetector, logger)
		r.Use(aiSecurityMiddleware.GinMiddleware())
	}
	
	// Add adaptive rate limiting middleware (uses AI if enabled, otherwise falls back to regular)
	var rateLimitMiddleware *ratelimit.RateLimitMiddleware
	if cfg.AIThreatDetectionEnabled {
		rateLimitMiddleware = ratelimit.NewRateLimitMiddleware(aiAdaptiveRateLimiter, logger, nil)
	} else {
		rateLimitMiddleware = ratelimit.NewRateLimitMiddleware(multiLayerLimiter, logger, nil)
	}
	r.Use(rateLimitMiddleware.GinMiddleware())
	
	// Add AI-enhanced content filtering middleware (uses AI if enabled, otherwise falls back to regular)
	var filterMiddleware *filter.Middleware
	if cfg.AIThreatDetectionEnabled {
		filterMiddleware = filter.NewMiddleware(aiEnhancedFilter, logger)
	} else {
		filterMiddleware = filter.NewMiddleware(contentFilter, logger)
	}
	r.Use(filterMiddleware.GinMiddleware())
	
	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	// Content filtering API
	filterAPI := filter.NewAPI(contentFilter, logger)
	apiGroup := r.Group("/api/v1/filter")
	filterAPI.RegisterRoutes(apiGroup)
	
	// Lists management API
	listsAPI := filter.NewListsAPI(listManager, logger)
	listsGroup := r.Group("/api/v1/lists")
	listsAPI.RegisterRoutes(listsGroup)
	
	// Rate limiting API
	rateLimitAPI := ratelimit.NewRateLimitAPI(bucketManager, multiLayerLimiter, bucketStorage, logger)
	rateLimitGroup := r.Group("/api/v1/ratelimit")
	rateLimitAPI.RegisterRoutes(rateLimitGroup)
	
	// User/Org limits API
	userOrgAPI := ratelimit.NewUserOrgLimitAPI(userOrgManager, logger)
	userOrgGroup := r.Group("/api/v1/limits")
	userOrgAPI.RegisterRoutes(userOrgGroup)
	
	// AI threat detection APIs (if enabled)
	if cfg.AIThreatDetectionEnabled {
		// AI threat detection API
		aiThreatAPI := ai.NewThreatDetectionAPI(aiThreatDetector, modelManager, metricsCollector, logger)
		aiGroup := r.Group("/api/v1/ai")
		aiThreatAPI.RegisterRoutes(aiGroup)
		
		// WebSocket endpoint for real-time monitoring
		r.GET("/ws/threats", wsHub.HandleWebSocket)
		
		// Health monitoring endpoint
		r.GET("/api/v1/ai/health", func(c *gin.Context) {
			status := healthMonitor.GetSystemStatus()
			c.JSON(200, status)
		})
		
		// Metrics endpoint (if enabled)
		if metricsCollector != nil {
			r.GET("/api/v1/ai/metrics", func(c *gin.Context) {
				snapshot := metricsCollector.GetSnapshot()
				c.JSON(200, snapshot)
			})
		}
		
		// Alert management endpoints (if enabled)
		if alertManager != nil {
			r.GET("/api/v1/ai/alerts", func(c *gin.Context) {
				alerts := alertManager.GetActiveAlerts()
				c.JSON(200, alerts)
			})
			
			r.POST("/api/v1/ai/alerts/:id/acknowledge", func(c *gin.Context) {
				alertID := c.Param("id")
				acknowledgedBy := c.GetHeader("X-User-ID")
				if acknowledgedBy == "" {
					acknowledgedBy = "system"
				}
				
				err := alertManager.AcknowledgeAlert(alertID, acknowledgedBy)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}
				
				c.JSON(200, gin.H{"status": "acknowledged"})
			})
			
			r.POST("/api/v1/ai/alerts/:id/resolve", func(c *gin.Context) {
				alertID := c.Param("id")
				
				err := alertManager.ResolveAlert(alertID)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}
				
				c.JSON(200, gin.H{"status": "resolved"})
			})
		}
	}
	
	// Start services
	go socks5Server.Start()
	go httpProxy.Start()
	
	// Start HTTP server
	srv := &http.Server{
		Addr:    ":" + cfg.APIPort,
		Handler: r,
	}
	
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()
	
	logger.Info("Proxy server started with content filtering enabled")
	
	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	logger.Info("Shutting down server...")
	
	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("Server forced to shutdown:", err)
	}
	
	// Shutdown AI components if enabled
	if cfg.AIThreatDetectionEnabled {
		logger.Info("Shutting down AI threat detection system...")
		
		// Stop alert manager
		if alertManager != nil {
			if err := alertManager.Stop(); err != nil {
				logger.Errorf("Error stopping alert manager: %v", err)
			}
		}
		
		// Stop WebSocket hub
		wsHub.Stop()
		
		// Stop adaptive learning
		adaptiveLearning.Stop()
		
		// Stop threat intelligence updates
		threatIntelligence.Stop()
		
		// Stop health monitor
		healthMonitor.Stop()
		
		logger.Info("AI threat detection system stopped")
	}
	
	// Close Redis connection
	redisClient.Close()
	
	logger.Info("Server exiting")
}

// createDefaultRules creates some default filtering rules if none exist
func createDefaultRules(ctx context.Context, contentFilter filter.ContentFilter, logger *logging.Logger) error {
	rules, err := contentFilter.GetRules(ctx)
	if err != nil {
		return err
	}
	
	// If rules already exist, don't create defaults
	if len(rules) > 0 {
		return nil
	}
	
	defaultRules := []*filter.FilterRule{
		{
			ID:          "block-malware-domains",
			Name:        "Block Known Malware Domains",
			Pattern:     "malware-example.com",
			Type:        filter.RuleTypeDomain,
			Action:      filter.ActionBlock,
			Priority:    1000,
			Enabled:     true,
			Description: "Blocks access to known malware domains",
		},
		{
			ID:          "block-exe-downloads",
			Name:        "Block Executable Downloads",
			Pattern:     ".exe",
			Type:        filter.RuleTypeFileExtension,
			Action:      filter.ActionBlock,
			Priority:    800,
			Enabled:     true,
			Description: "Blocks downloading of executable files",
		},
		{
			ID:          "log-admin-access",
			Name:        "Log Admin Panel Access",
			Pattern:     "admin",
			Type:        filter.RuleTypeURL,
			Action:      filter.ActionLog,
			Priority:    500,
			Enabled:     true,
			Description: "Logs access to admin panels",
		},
		{
			ID:          "block-social-media",
			Name:        "Block Social Media",
			Pattern:     "facebook.com",
			Type:        filter.RuleTypeDomain,
			Action:      filter.ActionBlock,
			Priority:    300,
			Enabled:     false, // Disabled by default
			Description: "Blocks access to Facebook",
		},
	}
	
	for _, rule := range defaultRules {
		if err := contentFilter.AddRule(ctx, rule); err != nil {
			logger.Errorf("Failed to create default rule %s: %v", rule.Name, err)
		} else {
			logger.Infof("Created default rule: %s", rule.Name)
		}
	}
	
	return nil
}

// createDefaultBlacklist creates some default blacklist entries if none exist
func createDefaultBlacklist(ctx context.Context, listManager filter.ListManager, logger *logging.Logger) error {
	stats, err := listManager.GetStats(ctx)
	if err != nil {
		return err
	}
	
	// If entries already exist, don't create defaults
	if stats.BlacklistEntries > 0 {
		return nil
	}
	
	defaultBlacklist := []string{
		"malware-example.com",
		"phishing-site.com",
		"dangerous-domain.net",
		"spam-site.org",
	}
	
	result, err := listManager.ImportEntries(ctx, 
		filter.ListTypeBlacklist, 
		filter.SourceManual, 
		defaultBlacklist, 
		filter.CategoryMalware)
	
	if err != nil {
		return err
	}
	
	logger.Infof("Created %d default blacklist entries", result.Added)
	return nil
}

// createDefaultRateLimitConfigs creates default rate limiting configurations
func createDefaultRateLimitConfigs(ctx context.Context, manager *ratelimit.TokenBucketManager, logger *logging.Logger) error {
	configs := map[string]*ratelimit.BucketConfig{
		"default_user": {
			Capacity:   100,  // 100 requests
			RefillRate: 10,   // 10 requests per second
		},
		"default_ip": {
			Capacity:   1000, // 1000 requests
			RefillRate: 50,   // 50 requests per second
		},
		"default_org": {
			Capacity:   10000, // 10000 requests
			RefillRate: 500,   // 500 requests per second
		},
		"premium_user": {
			Capacity:   500,  // 500 requests
			RefillRate: 50,   // 50 requests per second
		},
		"api_endpoint": {
			Capacity:   200,  // 200 requests
			RefillRate: 20,   // 20 requests per second
		},
	}
	
	for name, config := range configs {
		if err := manager.SetConfig(ctx, name, config); err != nil {
			logger.Errorf("Failed to create rate limit config %s: %v", name, err)
		} else {
			logger.Infof("Created rate limit config: %s (capacity=%d, refill_rate=%d)", 
				name, config.Capacity, config.RefillRate)
		}
	}
	
	return nil
}//
 createDefaultUserOrgLimits creates default user and organization limits
func createDefaultUserOrgLimits(ctx context.Context, manager *ratelimit.UserOrgLimitManager, logger *logging.Logger) error {
	// Create sample user limits
	sampleUserLimits := []*ratelimit.UserLimits{
		{
			UserID:           "demo_user_free",
			OrgID:            "demo_org",
			Tier:             "free",
			RequestsPerHour:  100,
			RequestsPerDay:   1000,
			RequestsPerMonth: 10000,
			BandwidthPerDay:  100 * 1024 * 1024,  // 100MB
			BandwidthPerMonth: 1024 * 1024 * 1024, // 1GB
			ConcurrentConns:  5,
			Enabled:          true,
		},
		{
			UserID:           "demo_user_premium",
			OrgID:            "demo_org",
			Tier:             "premium",
			RequestsPerHour:  10000,
			RequestsPerDay:   100000,
			RequestsPerMonth: 1000000,
			BandwidthPerDay:  10 * 1024 * 1024 * 1024,   // 10GB
			BandwidthPerMonth: 100 * 1024 * 1024 * 1024,  // 100GB
			ConcurrentConns:  100,
			Enabled:          true,
		},
	}
	
	for _, limits := range sampleUserLimits {
		if err := manager.SetUserLimits(ctx, limits); err != nil {
			logger.Errorf("Failed to create sample user limits for %s: %v", limits.UserID, err)
		} else {
			logger.Infof("Created sample user limits: %s (tier: %s)", limits.UserID, limits.Tier)
		}
	}
	
	// Create sample org limits
	sampleOrgLimits := []*ratelimit.OrgLimits{
		{
			OrgID:            "demo_org",
			Plan:             "business",
			RequestsPerHour:  50000,
			RequestsPerDay:   500000,
			RequestsPerMonth: 5000000,
			BandwidthPerDay:  50 * 1024 * 1024 * 1024,   // 50GB
			BandwidthPerMonth: 500 * 1024 * 1024 * 1024,  // 500GB
			MaxUsers:         100,
			MaxConcurrentConns: 1000,
			Features:         []string{"advanced_analytics", "priority_support", "custom_rules"},
			Enabled:          true,
		},
		{
			OrgID:            "enterprise_org",
			Plan:             "enterprise",
			RequestsPerHour:  500000,
			RequestsPerDay:   5000000,
			RequestsPerMonth: 50000000,
			BandwidthPerDay:  500 * 1024 * 1024 * 1024,  // 500GB
			BandwidthPerMonth: 5000 * 1024 * 1024 * 1024, // 5TB
			MaxUsers:         1000,
			MaxConcurrentConns: 10000,
			Features:         []string{"full_analytics", "24x7_support", "custom_rules", "white_label", "sla"},
			Enabled:          true,
		},
	}
	
	for _, limits := range sampleOrgLimits {
		if err := manager.SetOrgLimits(ctx, limits); err != nil {
			logger.Errorf("Failed to create sample org limits for %s: %v", limits.OrgID, err)
		} else {
			logger.Infof("Created sample org limits: %s (plan: %s)", limits.OrgID, limits.Plan)
		}
	}
	
	return nil
}