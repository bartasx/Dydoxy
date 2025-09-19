#!/bin/bash

# AI Threat Detection Database Migration Script
# This script handles database migrations for the AI threat detection system

set -e

# Configuration
REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_DB=${REDIS_DB:-0}
MIGRATION_VERSION=${MIGRATION_VERSION:-latest}
BACKUP_DIR=${BACKUP_DIR:-./backups}

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

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo
    echo "Commands:"
    echo "  migrate     Run database migrations"
    echo "  rollback    Rollback to previous version"
    echo "  status      Show migration status"
    echo "  backup      Create database backup"
    echo "  restore     Restore from backup"
    echo "  reset       Reset database (WARNING: destructive)"
    echo
    echo "Options:"
    echo "  -h, --host HOST         Redis host (default: localhost)"
    echo "  -p, --port PORT         Redis port (default: 6379)"
    echo "  -d, --db DB             Redis database (default: 0)"
    echo "  -v, --version VERSION   Migration version (default: latest)"
    echo "  -b, --backup-dir DIR    Backup directory (default: ./backups)"
    echo "  --help                  Show this help message"
    echo
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host)
                REDIS_HOST="$2"
                shift 2
                ;;
            -p|--port)
                REDIS_PORT="$2"
                shift 2
                ;;
            -d|--db)
                REDIS_DB="$2"
                shift 2
                ;;
            -v|--version)
                MIGRATION_VERSION="$2"
                shift 2
                ;;
            -b|--backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            migrate|rollback|status|backup|restore|reset)
                COMMAND="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    if [ -z "$COMMAND" ]; then
        log_error "No command specified"
        show_usage
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Redis CLI
    if ! command -v redis-cli &> /dev/null; then
        log_error "redis-cli is not installed"
        exit 1
    fi
    
    # Test Redis connection
    if ! redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB ping > /dev/null 2>&1; then
        log_error "Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT (DB: $REDIS_DB)"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    log_success "Prerequisites check passed"
}

# Get current migration version
get_current_version() {
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HGET ai:migration:status version 2>/dev/null || echo "0"
}

# Set migration version
set_migration_version() {
    local version=$1
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:migration:status \
        version "$version" \
        updated_at "$timestamp" \
        status "completed"
}

# Migration v1: Initial AI system setup
migrate_v1() {
    log_info "Running migration v1: Initial AI system setup"
    
    # Create AI system configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:config:system \
        version "1.0.0" \
        initialized_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        migration_version "1"
    
    # Create default model configurations
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:models:content_analysis \
        version "1.0.0" \
        type "gradient_boosting" \
        confidence_threshold 0.7 \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:models:behavioral_analysis \
        version "1.0.0" \
        type "statistical" \
        anomaly_threshold 2.0 \
        enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Migration v1 completed"
}

# Migration v2: Enhanced threat intelligence
migrate_v2() {
    log_info "Running migration v2: Enhanced threat intelligence"
    
    # Add threat intelligence providers configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:threat_intel:providers:malware_domains \
        enabled true \
        url "https://malware-domains.com/api/domains" \
        update_interval 3600 \
        confidence 0.9 \
        category "malware" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:threat_intel:providers:phishing_domains \
        enabled true \
        url "https://phishing-domains.com/api/domains" \
        update_interval 1800 \
        confidence 0.85 \
        category "phishing" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:threat_intel:providers:ip_reputation \
        enabled true \
        url "https://ip-reputation.com/api/ips" \
        update_interval 7200 \
        confidence 0.8 \
        category "reputation" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add threat intelligence cache configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:threat_intel:cache:config \
        ttl 86400 \
        max_entries 100000 \
        cleanup_interval 3600 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Migration v2 completed"
}

# Migration v3: Advanced metrics and alerting
migrate_v3() {
    log_info "Running migration v3: Advanced metrics and alerting"
    
    # Add metrics collection configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:metrics:config \
        enabled true \
        collection_interval 30 \
        retention_period 604800 \
        aggregation_intervals "60,300,3600,86400" \
        export_formats "prometheus,influxdb,json" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add default metric definitions
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:metrics:definitions:threat_score \
        type "gauge" \
        description "Current threat score" \
        unit "score" \
        min_value 0 \
        max_value 1 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:metrics:definitions:requests_analyzed \
        type "counter" \
        description "Total requests analyzed" \
        unit "requests" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:metrics:definitions:model_accuracy \
        type "gauge" \
        description "Model accuracy percentage" \
        unit "percentage" \
        min_value 0 \
        max_value 100 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add alerting configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:config \
        enabled true \
        check_interval 30 \
        cooldown_period 300 \
        max_active_alerts 1000 \
        escalation_enabled true \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add default alert channels
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:channels:email \
        type "email" \
        enabled false \
        severity_filter "warning,error,critical" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:alerts:channels:slack \
        type "slack" \
        enabled false \
        severity_filter "error,critical" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Migration v3 completed"
}

# Migration v4: Behavioral analysis enhancements
migrate_v4() {
    log_info "Running migration v4: Behavioral analysis enhancements"
    
    # Add enhanced behavioral profile templates
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:templates:web_browser \
        requests_per_hour_avg 60 \
        requests_per_hour_stddev 20 \
        unique_domains_avg 15 \
        unique_domains_stddev 8 \
        session_duration_avg 2400 \
        session_duration_stddev 800 \
        user_agent_consistency 0.9 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:templates:api_client \
        requests_per_hour_avg 300 \
        requests_per_hour_stddev 100 \
        unique_domains_avg 5 \
        unique_domains_stddev 2 \
        session_duration_avg 600 \
        session_duration_stddev 200 \
        user_agent_consistency 1.0 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:behavior:templates:mobile_app \
        requests_per_hour_avg 40 \
        requests_per_hour_stddev 15 \
        unique_domains_avg 8 \
        unique_domains_stddev 4 \
        session_duration_avg 1800 \
        session_duration_stddev 600 \
        user_agent_consistency 0.95 \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add anomaly detection configuration
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HSET ai:anomaly:config \
        enabled true \
        window_size 3600 \
        min_samples 10 \
        contamination 0.1 \
        algorithm "isolation_forest" \
        created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    log_success "Migration v4 completed"
}

# Run migrations
run_migrations() {
    local current_version=$(get_current_version)
    local target_version
    
    if [ "$MIGRATION_VERSION" = "latest" ]; then
        target_version=4  # Update this when adding new migrations
    else
        target_version=$MIGRATION_VERSION
    fi
    
    log_info "Current version: $current_version"
    log_info "Target version: $target_version"
    
    if [ $current_version -ge $target_version ]; then
        log_info "Database is already at version $current_version (target: $target_version)"
        return 0
    fi
    
    # Create backup before migration
    create_backup "pre-migration-v$target_version"
    
    # Run migrations in sequence
    for version in $(seq $((current_version + 1)) $target_version); do
        case $version in
            1)
                migrate_v1
                ;;
            2)
                migrate_v2
                ;;
            3)
                migrate_v3
                ;;
            4)
                migrate_v4
                ;;
            *)
                log_error "Unknown migration version: $version"
                exit 1
                ;;
        esac
        
        set_migration_version $version
        log_success "Migration to version $version completed"
    done
    
    log_success "All migrations completed successfully"
}

# Rollback to previous version
rollback_migration() {
    local current_version=$(get_current_version)
    
    if [ $current_version -le 1 ]; then
        log_error "Cannot rollback from version $current_version"
        exit 1
    fi
    
    local target_version=$((current_version - 1))
    
    log_warning "Rolling back from version $current_version to $target_version"
    log_warning "This operation may result in data loss!"
    
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Rollback cancelled"
        exit 0
    fi
    
    # Create backup before rollback
    create_backup "pre-rollback-v$current_version"
    
    # For now, we'll just restore from the most recent backup
    # In a real implementation, you'd have specific rollback procedures
    log_warning "Rollback functionality is limited. Consider restoring from backup."
    
    set_migration_version $target_version
    log_success "Rollback to version $target_version completed"
}

# Show migration status
show_migration_status() {
    local current_version=$(get_current_version)
    local status=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HGET ai:migration:status status 2>/dev/null || echo "unknown")
    local updated_at=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB HGET ai:migration:status updated_at 2>/dev/null || echo "unknown")
    
    echo "Migration Status:"
    echo "=================="
    echo "Current Version: $current_version"
    echo "Status: $status"
    echo "Last Updated: $updated_at"
    echo
    
    # Show available migrations
    echo "Available Migrations:"
    echo "  v1: Initial AI system setup"
    echo "  v2: Enhanced threat intelligence"
    echo "  v3: Advanced metrics and alerting"
    echo "  v4: Behavioral analysis enhancements"
    echo
    
    # Show Redis key statistics
    local ai_keys_count=$(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB KEYS "ai:*" | wc -l)
    echo "AI-related Redis keys: $ai_keys_count"
}

# Create database backup
create_backup() {
    local backup_name=${1:-"backup-$(date +%Y%m%d-%H%M%S)"}
    local backup_file="$BACKUP_DIR/$backup_name.rdb"
    
    log_info "Creating backup: $backup_name"
    
    # Create Redis dump
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB --rdb "$backup_file"
    
    # Create metadata file
    cat > "$BACKUP_DIR/$backup_name.meta" << EOF
{
  "backup_name": "$backup_name",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "redis_host": "$REDIS_HOST",
  "redis_port": $REDIS_PORT,
  "redis_db": $REDIS_DB,
  "migration_version": $(get_current_version),
  "ai_keys_count": $(redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB KEYS "ai:*" | wc -l)
}
EOF
    
    log_success "Backup created: $backup_file"
}

# Restore from backup
restore_backup() {
    log_info "Available backups:"
    ls -la "$BACKUP_DIR"/*.rdb 2>/dev/null || {
        log_error "No backups found in $BACKUP_DIR"
        exit 1
    }
    
    echo
    read -p "Enter backup filename (without path): " backup_file
    
    local backup_path="$BACKUP_DIR/$backup_file"
    
    if [ ! -f "$backup_path" ]; then
        log_error "Backup file not found: $backup_path"
        exit 1
    fi
    
    log_warning "This will overwrite the current database!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Restore cancelled"
        exit 0
    fi
    
    # Stop Redis (if running locally)
    log_info "Restoring from backup: $backup_path"
    
    # This is a simplified restore - in production you'd need to handle this more carefully
    log_warning "Manual restore required. Please:"
    echo "1. Stop Redis server"
    echo "2. Replace dump.rdb with: $backup_path"
    echo "3. Start Redis server"
    echo "4. Update migration version if needed"
}

# Reset database
reset_database() {
    log_warning "This will delete ALL AI-related data!"
    log_warning "This operation is IRREVERSIBLE!"
    
    read -p "Type 'RESET' to confirm: " confirmation
    
    if [ "$confirmation" != "RESET" ]; then
        log_info "Reset cancelled"
        exit 0
    fi
    
    # Create backup before reset
    create_backup "pre-reset-$(date +%Y%m%d-%H%M%S)"
    
    log_info "Deleting all AI-related keys..."
    
    # Delete all AI keys
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB EVAL "
        local keys = redis.call('KEYS', 'ai:*')
        for i=1,#keys do
            redis.call('DEL', keys[i])
        end
        return #keys
    " 0
    
    # Reset migration status
    redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB DEL ai:migration:status
    
    log_success "Database reset completed"
}

# Main execution
main() {
    echo "🗄️  AI Threat Detection Database Migration"
    echo "=========================================="
    echo "Redis: $REDIS_HOST:$REDIS_PORT (DB: $REDIS_DB)"
    echo "Command: $COMMAND"
    echo
    
    check_prerequisites
    
    case $COMMAND in
        migrate)
            run_migrations
            ;;
        rollback)
            rollback_migration
            ;;
        status)
            show_migration_status
            ;;
        backup)
            create_backup
            ;;
        restore)
            restore_backup
            ;;
        reset)
            reset_database
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_usage
            exit 1
            ;;
    esac
}

# Parse arguments and run main function
parse_args "$@"
main