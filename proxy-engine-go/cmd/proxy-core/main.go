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
	"	"github.com/dydoxy/proxy-engine-go/internal/security/filter"
	"github.com/dydoxy/proxy-engine-go/internal/security/ratelimit""
)

func main() {
	// Initialize configuration
	cfg := config.Load()
	
	// Initialize logging
	logger := logging.NewLogger(cfg.LogLevel)
	
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	
	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
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
	
	// Create default rate limit configurations
	if err := createDefaultRateLimitConfigs(ctx, bucketManager, logger); err != nil {
		logger.Warnf("Failed to create default rate limit configs: %v", err)
	}
	
	// Initialize multi-layer rate limiter
	multiLayerLimiter := ratelimit.NewMultiLayerRateLimiter(bucketManager, logger)
	
	// Add rate limiting strategies
	multiLayerLimiter.AddStrategy(ratelimit.NewPerUserStrategy("default_user"))
	multiLayerLimiter.AddStrategy(ratelimit.NewPerIPStrategy("default_ip"))
	multiLayerLimiter.AddStrategy(ratelimit.NewPerOrgStrategy("default_org"))
	
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
	
	// Add rate limiting middleware
	rateLimitMiddleware := ratelimit.NewRateLimitMiddleware(multiLayerLimiter, logger, nil)
	r.Use(rateLimitMiddleware.GinMiddleware())
	
	// Add content filtering middleware
	filterMiddleware := filter.NewMiddleware(contentFilter, logger)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown:", err)
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
}