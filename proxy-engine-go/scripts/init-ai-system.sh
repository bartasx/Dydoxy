#!/bin/bash

# AI Threat Detection System Initialization Script
# This script initializes the AI threat detection system with default models and configurations

set -e

echo "🤖 Initializing AI Threat Detection System..."

# Configuration
REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_DB=${REDIS_DB:-0}
AI_MODELS_DIR=${AI_MODELS_DIR:-./models}
AI_DATA_DIR=${AI_DATA_DIR:-./data}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check if Redis is available
    if ! command -v redis-cli &> /dev/null; then
        log_error "redis-cli is not installed. Please install Redis client."
        exit 1
    fi
    
    # Test Redis connection
    if ! redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB ping > /dev/null 2>&1; then
        log_error "Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT (DB: $REDIS_DB)"
        exit 1
    fi
    
    log_success "Dependencies check passed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p $AI_MODELS_DIR
    mkdir -p $AI_DATA_DIR
    mkdir -p $AI_DATA_DIR/training
    mkdir -p $AI_DATA_DIR/cache
    mkdir -p $AI_DATA_DIR/logs
    mkdir -p $AI_DATA_DIR/metrics
    
    log_success "Directories created"
}

# Initialize Redis keys for AI system
init_redis_keys() {
    log_info "Initializing Redis keys for AI system..."
    
    # AI system configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:system \
        enabled true \
        version "1.0.0" \
        initialized_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        models_path "$AI_MODELS_DIR" \
        data_path "$AI_DATA_DIR"
    
    # Content analysis model configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:content_analysis \
        enabled true \
        confidence_threshold 0.7 \
        max_processing_time 5000 \
        model_version "1.0.0" \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Behavioral analysis configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:behavioral_analysis \
        enabled true \
        window_size 3600 \
        anomaly_threshold 2.0 \
        min_samples 10 \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Threat intelligence configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:threat_intelligence \
        enabled true \
        update_interval 3600 \
        cache_ttl 86400 \
        providers "malware_domains,phishing_domains,ip_reputation" \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Metrics configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:metrics \
        enabled true \
        collection_interval 30 \
        retention_period 604800 \
        export_enabled false \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Alerting configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:alerting \
        enabled true \
        check_interval 30 \
        cooldown_period 300 \
        max_active_alerts 1000 \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Redis keys initialized"
}

# Initialize default threat intelligence data
init_threat_intelligence() {
    log_info "Initializing threat intelligence data..."
    
    # Sample malicious domains
    cat > /tmp/malicious_domains.txt << EOF
malware-example.com
phishing-site.net
dangerous-domain.org
spam-website.com
trojan-host.info
botnet-c2.biz
fake-bank.co
scam-site.net
malicious-ads.com
exploit-kit.org
EOF
    
    # Load malicious domains into Redis
    while IFS= read -r domain; do
        redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET "ai:threat_intel:domains:$domain" \
            type "malicious" \
            category "malware" \
            confidence 0.9 \
            source "manual" \
            added_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            expires_at "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)"
        
        redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB SADD ai:threat_intel:domains:set "$domain"
    done < /tmp/malicious_domains.txt
    
    # Sample malicious IPs
    cat > /tmp/malicious_ips.txt << EOF
192.0.2.1
198.51.100.1
203.0.113.1
10.0.0.1
172.16.0.1
EOF
    
    # Load malicious IPs into Redis
    while IFS= read -r ip; do
        redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET "ai:threat_intel:ips:$ip" \
            type "malicious" \
            category "botnet" \
            confidence 0.8 \
            source "manual" \
            added_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            expires_at "$(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)"
        
        redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB SADD ai:threat_intel:ips:set "$ip"
    done < /tmp/malicious_ips.txt
    
    # Set threat intelligence statistics
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:threat_intel:stats \
        domains_count 10 \
        ips_count 5 \
        last_updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        next_update "$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)"
    
    # Cleanup temp files
    rm -f /tmp/malicious_domains.txt /tmp/malicious_ips.txt
    
    log_success "Threat intelligence data initialized"
}

# Initialize default behavioral profiles
init_behavioral_profiles() {
    log_info "Initializing behavioral profiles..."
    
    # Create sample behavioral profiles for different user types
    
    # Normal user profile
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:profile:normal_user \
        requests_per_hour_avg 50 \
        requests_per_hour_stddev 15 \
        unique_domains_avg 10 \
        unique_domains_stddev 5 \
        session_duration_avg 1800 \
        session_duration_stddev 600 \
        error_rate_avg 0.02 \
        error_rate_stddev 0.01 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Power user profile
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:profile:power_user \
        requests_per_hour_avg 200 \
        requests_per_hour_stddev 50 \
        unique_domains_avg 50 \
        unique_domains_stddev 20 \
        session_duration_avg 3600 \
        session_duration_stddev 1200 \
        error_rate_avg 0.01 \
        error_rate_stddev 0.005 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Bot profile (suspicious)
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:profile:bot \
        requests_per_hour_avg 1000 \
        requests_per_hour_stddev 100 \
        unique_domains_avg 5 \
        unique_domains_stddev 2 \
        session_duration_avg 60 \
        session_duration_stddev 30 \
        error_rate_avg 0.1 \
        error_rate_stddev 0.05 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Behavioral profiles initialized"
}

# Initialize default alert thresholds
init_alert_thresholds() {
    log_info "Initializing alert thresholds..."
    
    # High error rate threshold
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:threshold:high_error_rate \
        metric_name "error_rate" \
        operator ">" \
        value 0.1 \
        duration 300 \
        severity "warning" \
        description "High error rate detected" \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # High threat score threshold
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:threshold:high_threat_score \
        metric_name "threat_score" \
        operator ">" \
        value 0.8 \
        duration 60 \
        severity "critical" \
        description "High threat score detected" \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Anomaly detection threshold
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:threshold:behavioral_anomaly \
        metric_name "anomaly_score" \
        operator ">" \
        value 2.0 \
        duration 180 \
        severity "warning" \
        description "Behavioral anomaly detected" \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Model performance threshold
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:threshold:model_performance \
        metric_name "model_accuracy" \
        operator "<" \
        value 0.8 \
        duration 600 \
        severity "error" \
        description "Model performance degraded" \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Alert thresholds initialized"
}

# Initialize sample training data
init_training_data() {
    log_info "Initializing sample training data..."
    
    # Create sample training data for content analysis
    cat > $AI_DATA_DIR/training/content_samples.json << EOF
{
  "benign_samples": [
    {
      "url": "https://www.google.com/search?q=weather",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "content_type": "text/html",
      "label": "benign",
      "features": {
        "url_length": 42,
        "domain_age": 365,
        "has_https": true,
        "suspicious_keywords": 0
      }
    },
    {
      "url": "https://github.com/user/repo",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "content_type": "text/html",
      "label": "benign",
      "features": {
        "url_length": 28,
        "domain_age": 180,
        "has_https": true,
        "suspicious_keywords": 0
      }
    }
  ],
  "malicious_samples": [
    {
      "url": "http://malware-example.com/download.exe",
      "user_agent": "wget/1.20.3",
      "content_type": "application/octet-stream",
      "label": "malicious",
      "features": {
        "url_length": 38,
        "domain_age": 1,
        "has_https": false,
        "suspicious_keywords": 2
      }
    },
    {
      "url": "https://phishing-site.net/login?redirect=bank.com",
      "user_agent": "Mozilla/5.0 (compatible; bot/1.0)",
      "content_type": "text/html",
      "label": "malicious",
      "features": {
        "url_length": 48,
        "domain_age": 0,
        "has_https": true,
        "suspicious_keywords": 3
      }
    }
  ]
}
EOF
    
    # Create sample behavioral training data
    cat > $AI_DATA_DIR/training/behavioral_samples.json << EOF
{
  "normal_behavior": [
    {
      "user_id": "user_001",
      "requests_per_hour": 45,
      "unique_domains": 8,
      "session_duration": 1650,
      "error_rate": 0.02,
      "label": "normal"
    },
    {
      "user_id": "user_002",
      "requests_per_hour": 62,
      "unique_domains": 12,
      "session_duration": 2100,
      "error_rate": 0.01,
      "label": "normal"
    }
  ],
  "anomalous_behavior": [
    {
      "user_id": "bot_001",
      "requests_per_hour": 950,
      "unique_domains": 3,
      "session_duration": 45,
      "error_rate": 0.15,
      "label": "anomalous"
    },
    {
      "user_id": "scraper_001",
      "requests_per_hour": 1200,
      "unique_domains": 1,
      "session_duration": 30,
      "error_rate": 0.08,
      "label": "anomalous"
    }
  ]
}
EOF
    
    log_success "Sample training data created"
}

# Verify initialization
verify_initialization() {
    log_info "Verifying AI system initialization..."
    
    # Check Redis keys
    local keys_count=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB KEYS "ai:*" | wc -l)
    if [ $keys_count -lt 10 ]; then
        log_error "Expected at least 10 AI-related keys in Redis, found $keys_count"
        return 1
    fi
    
    # Check directories
    for dir in "$AI_MODELS_DIR" "$AI_DATA_DIR" "$AI_DATA_DIR/training" "$AI_DATA_DIR/cache"; do
        if [ ! -d "$dir" ]; then
            log_error "Directory $dir was not created"
            return 1
        fi
    done
    
    # Check training data files
    if [ ! -f "$AI_DATA_DIR/training/content_samples.json" ]; then
        log_error "Content training samples file not found"
        return 1
    fi
    
    if [ ! -f "$AI_DATA_DIR/training/behavioral_samples.json" ]; then
        log_error "Behavioral training samples file not found"
        return 1
    fi
    
    log_success "AI system initialization verified"
    return 0
}

# Print system status
print_status() {
    log_info "AI Threat Detection System Status:"
    echo
    echo "📁 Directories:"
    echo "   Models: $AI_MODELS_DIR"
    echo "   Data: $AI_DATA_DIR"
    echo
    echo "🔧 Redis Configuration:"
    echo "   Host: $REDIS_HOST"
    echo "   Port: $REDIS_PORT"
    echo "   Database: $REDIS_DB"
    echo
    echo "📊 Redis Keys:"
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB KEYS "ai:*" | sed 's/^/   /'
    echo
    echo "🎯 Threat Intelligence:"
    local domains_count=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB SCARD ai:threat_intel:domains:set)
    local ips_count=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB SCARD ai:threat_intel:ips:set)
    echo "   Malicious domains: $domains_count"
    echo "   Malicious IPs: $ips_count"
    echo
}

# Main execution
main() {
    echo "🚀 Starting AI Threat Detection System Initialization"
    echo "=================================================="
    
    check_dependencies
    create_directories
    init_redis_keys
    init_threat_intelligence
    init_behavioral_profiles
    init_alert_thresholds
    init_training_data
    
    if verify_initialization; then
        print_status
        log_success "AI Threat Detection System initialization completed successfully!"
        echo
        echo "🎉 The system is now ready to use. You can start the proxy-core service."
        echo "   Environment variables used:"
        echo "   - REDIS_HOST=$REDIS_HOST"
        echo "   - REDIS_PORT=$REDIS_PORT"
        echo "   - REDIS_DB=$REDIS_DB"
        echo "   - AI_MODELS_DIR=$AI_MODELS_DIR"
        echo "   - AI_DATA_DIR=$AI_DATA_DIR"
    else
        log_error "AI system initialization failed verification"
        exit 1
    fi
}

# Run main function
main "$@"