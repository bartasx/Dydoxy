package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	SOCKS5Port string
	HTTPPort   string
	APIPort    string
	LogLevel   string
	Database   DatabaseConfig
	Redis      RedisConfig
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
}

func Load() *Config {
	viper.SetDefault("socks5_port", "1080")
	viper.SetDefault("http_port", "8080")
	viper.SetDefault("api_port", "9090")
	viper.SetDefault("log_level", "info")
	
	viper.AutomaticEnv()
	
	return &Config{
		SOCKS5Port: viper.GetString("socks5_port"),
		HTTPPort:   viper.GetString("http_port"),
		APIPort:    viper.GetString("api_port"),
		LogLevel:   viper.GetString("log_level"),
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
		},
	}
}