package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	SOCKS5Port                string
	HTTPPort                  string
	APIPort                   string
	LogLevel                  string
	Database                  DatabaseConfig
	Redis                     RedisConfig
	AIThreatDetectionEnabled  bool
	AIThreatDetection         AIThreatDetectionConfig
}

type AIThreatDetectionConfig struct {
	Enabled                    bool
	ContentAnalysisEnabled     bool
	BehavioralAnalysisEnabled  bool
	AnomalyDetectionEnabled    bool
	ThreatIntelligenceEnabled  bool
	AdaptiveLearningEnabled    bool
	ConfidenceThreshold        float64
	MaxProcessingTimeSeconds   int
	EnableRealTimeUpdates      bool
	ModelUpdateIntervalHours   int
	MetricsEnabled             bool
	AlertingEnabled            bool
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

func Load() *Config {
	viper.SetDefault("socks5_port", "1080")
	viper.SetDefault("http_port", "8080")
	viper.SetDefault("api_port", "9090")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("redis_host", "localhost")
	viper.SetDefault("redis_port", "6379")
	viper.SetDefault("redis_db", 0)
	
	// AI Threat Detection defaults
	viper.SetDefault("ai_threat_detection_enabled", true)
	viper.SetDefault("ai_content_analysis_enabled", true)
	viper.SetDefault("ai_behavioral_analysis_enabled", true)
	viper.SetDefault("ai_anomaly_detection_enabled", true)
	viper.SetDefault("ai_threat_intelligence_enabled", true)
	viper.SetDefault("ai_adaptive_learning_enabled", true)
	viper.SetDefault("ai_confidence_threshold", 0.7)
	viper.SetDefault("ai_max_processing_time_seconds", 5)
	viper.SetDefault("ai_enable_real_time_updates", true)
	viper.SetDefault("ai_model_update_interval_hours", 24)
	viper.SetDefault("ai_metrics_enabled", true)
	viper.SetDefault("ai_alerting_enabled", true)
	
	viper.AutomaticEnv()
	
	return &Config{
		SOCKS5Port:               viper.GetString("socks5_port"),
		HTTPPort:                 viper.GetString("http_port"),
		APIPort:                  viper.GetString("api_port"),
		LogLevel:                 viper.GetString("log_level"),
		AIThreatDetectionEnabled: viper.GetBool("ai_threat_detection_enabled"),
		Database: DatabaseConfig{
			Host:     viper.GetString("db_host"),
			Port:     viper.GetString("db_port"),
			User:     viper.GetString("db_user"),
			Password: viper.GetString("db_password"),
			DBName:   viper.GetString("db_name"),
		},
		Redis: RedisConfig{
			Host:     viper.GetString("redis_host"),
			Port:     viper.GetString("redis_port"),
			Password: viper.GetString("redis_password"),
			DB:       viper.GetInt("redis_db"),
		},
		AIThreatDetection: AIThreatDetectionConfig{
			Enabled:                    viper.GetBool("ai_threat_detection_enabled"),
			ContentAnalysisEnabled:     viper.GetBool("ai_content_analysis_enabled"),
			BehavioralAnalysisEnabled:  viper.GetBool("ai_behavioral_analysis_enabled"),
			AnomalyDetectionEnabled:    viper.GetBool("ai_anomaly_detection_enabled"),
			ThreatIntelligenceEnabled:  viper.GetBool("ai_threat_intelligence_enabled"),
			AdaptiveLearningEnabled:    viper.GetBool("ai_adaptive_learning_enabled"),
			ConfidenceThreshold:        viper.GetFloat64("ai_confidence_threshold"),
			MaxProcessingTimeSeconds:   viper.GetInt("ai_max_processing_time_seconds"),
			EnableRealTimeUpdates:      viper.GetBool("ai_enable_real_time_updates"),
			ModelUpdateIntervalHours:   viper.GetInt("ai_model_update_interval_hours"),
			MetricsEnabled:             viper.GetBool("ai_metrics_enabled"),
			AlertingEnabled:            viper.GetBool("ai_alerting_enabled"),
		},
	}
}