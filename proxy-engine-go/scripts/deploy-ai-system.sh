#!/bin/bash

# AI Threat Detection System Deployment Script
# This script handles deployment of the AI threat detection system

set -e

# Configuration
DEPLOYMENT_ENV=${DEPLOYMENT_ENV:-development}
SERVICE_NAME=${SERVICE_NAME:-proxy-core}
DOCKER_IMAGE=${DOCKER_IMAGE:-dydoxy/proxy-core}
DOCKER_TAG=${DOCKER_TAG:-latest}
HEALTH_CHECK_TIMEOUT=${HEALTH_CHECK_TIMEOUT:-300}
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-5}

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
    echo "  build       Build the Docker image"
    echo "  deploy      Deploy the service"
    echo "  start       Start the service"
    echo "  stop        Stop the service"
    echo "  restart     Restart the service"
    echo "  status      Show service status"
    echo "  logs        Show service logs"
    echo "  health      Check service health"
    echo "  cleanup     Clean up old deployments"
    echo
    echo "Options:"
    echo "  -e, --env ENV           Deployment environment (development, staging, production)"
    echo "  -t, --tag TAG           Docker image tag"
    echo "  -s, --service NAME      Service name"
    echo "  -h, --help              Show this help message"
    echo
    echo "Environment Variables:"
    echo "  DEPLOYMENT_ENV          Deployment environment"
    echo "  DOCKER_IMAGE            Docker image name"
    echo "  DOCKER_TAG              Docker image tag"
    echo "  SERVICE_NAME            Service name"
    echo "  HEALTH_CHECK_TIMEOUT    Health check timeout in seconds"
    echo
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--env)
                DEPLOYMENT_ENV="$2"
                shift 2
                ;;
            -t|--tag)
                DOCKER_TAG="$2"
                shift 2
                ;;
            -s|--service)
                SERVICE_NAME="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            build|deploy|start|stop|restart|status|logs|health|cleanup)
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
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build Docker image
build_image() {
    log_info "Building Docker image: $DOCKER_IMAGE:$DOCKER_TAG"
    
    # Create Dockerfile if it doesn't exist
    if [ ! -f "Dockerfile" ]; then
        create_dockerfile
    fi
    
    # Build the image
    docker build -t "$DOCKER_IMAGE:$DOCKER_TAG" .
    
    # Tag as latest if not already
    if [ "$DOCKER_TAG" != "latest" ]; then
        docker tag "$DOCKER_IMAGE:$DOCKER_TAG" "$DOCKER_IMAGE:latest"
    fi
    
    log_success "Docker image built successfully"
}

# Create Dockerfile
create_dockerfile() {
    log_info "Creating Dockerfile..."
    
    cat > Dockerfile << 'EOF'
# Multi-stage build for Go application
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o proxy-core ./cmd/proxy-core

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/proxy-core .

# Copy configuration files
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/scripts ./scripts

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/models && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 1080 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

# Set entrypoint
ENTRYPOINT ["./proxy-core"]
EOF
    
    log_success "Dockerfile created"
}

# Create docker-compose file
create_docker_compose() {
    log_info "Creating docker-compose.yml for $DEPLOYMENT_ENV environment..."
    
    cat > docker-compose.yml << EOF
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: ${SERVICE_NAME}-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  proxy-core:
    image: ${DOCKER_IMAGE}:${DOCKER_TAG}
    container_name: ${SERVICE_NAME}
    restart: unless-stopped
    ports:
      - "1080:1080"  # SOCKS5
      - "8080:8080"  # HTTP Proxy
      - "9090:9090"  # API
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - LOG_LEVEL=info
      - AI_THREAT_DETECTION_ENABLED=true
      - AI_CONTENT_ANALYSIS_ENABLED=true
      - AI_BEHAVIORAL_ANALYSIS_ENABLED=true
      - AI_ANOMALY_DETECTION_ENABLED=true
      - AI_THREAT_INTELLIGENCE_ENABLED=true
      - AI_ADAPTIVE_LEARNING_ENABLED=true
      - AI_CONFIDENCE_THRESHOLD=0.7
      - AI_MAX_PROCESSING_TIME_SECONDS=5
      - AI_METRICS_ENABLED=true
      - AI_ALERTING_ENABLED=true
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./models:/app/models
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:9090/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

volumes:
  redis_data:
    driver: local

networks:
  default:
    name: ${SERVICE_NAME}-network
EOF
    
    # Add environment-specific overrides
    case $DEPLOYMENT_ENV in
        production)
            cat >> docker-compose.yml << EOF

  # Production-specific configurations
  nginx:
    image: nginx:alpine
    container_name: ${SERVICE_NAME}-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - proxy-core
EOF
            ;;
        staging)
            # Add staging-specific configurations
            log_info "Using staging configuration"
            ;;
        development)
            # Add development-specific configurations
            log_info "Using development configuration"
            ;;
    esac
    
    log_success "docker-compose.yml created for $DEPLOYMENT_ENV environment"
}

# Deploy the service
deploy_service() {
    log_info "Deploying $SERVICE_NAME in $DEPLOYMENT_ENV environment..."
    
    # Create docker-compose file
    create_docker_compose
    
    # Pull latest images
    docker-compose pull
    
    # Stop existing services
    docker-compose down
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be healthy
    wait_for_health
    
    # Initialize AI system
    initialize_ai_system
    
    log_success "Service deployed successfully"
}

# Start the service
start_service() {
    log_info "Starting $SERVICE_NAME..."
    
    if [ ! -f "docker-compose.yml" ]; then
        create_docker_compose
    fi
    
    docker-compose up -d
    wait_for_health
    
    log_success "Service started successfully"
}

# Stop the service
stop_service() {
    log_info "Stopping $SERVICE_NAME..."
    
    docker-compose down
    
    log_success "Service stopped successfully"
}

# Restart the service
restart_service() {
    log_info "Restarting $SERVICE_NAME..."
    
    docker-compose restart
    wait_for_health
    
    log_success "Service restarted successfully"
}

# Show service status
show_status() {
    log_info "Service status:"
    echo
    
    if [ -f "docker-compose.yml" ]; then
        docker-compose ps
        echo
        
        # Show resource usage
        log_info "Resource usage:"
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
    else
        log_warning "docker-compose.yml not found. Service may not be deployed."
    fi
}

# Show service logs
show_logs() {
    log_info "Service logs:"
    
    if [ -f "docker-compose.yml" ]; then
        docker-compose logs -f --tail=100
    else
        log_error "docker-compose.yml not found"
        exit 1
    fi
}

# Check service health
check_health() {
    log_info "Checking service health..."
    
    local api_url="http://localhost:9090"
    
    # Check main health endpoint
    if curl -s -f "$api_url/health" > /dev/null; then
        log_success "Main service is healthy"
    else
        log_error "Main service is not healthy"
        return 1
    fi
    
    # Check AI system health
    if curl -s -f "$api_url/api/v1/ai/health" > /dev/null; then
        log_success "AI system is healthy"
        
        # Show AI system status
        local ai_status=$(curl -s "$api_url/api/v1/ai/health" | jq -r '.status // "unknown"')
        echo "   AI System Status: $ai_status"
    else
        log_warning "AI system health check failed"
    fi
    
    # Check Redis connection
    if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
        log_success "Redis is healthy"
    else
        log_error "Redis is not healthy"
        return 1
    fi
    
    return 0
}

# Wait for service health
wait_for_health() {
    log_info "Waiting for services to be healthy..."
    
    local timeout=$HEALTH_CHECK_TIMEOUT
    local interval=$HEALTH_CHECK_INTERVAL
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if check_health > /dev/null 2>&1; then
            log_success "All services are healthy"
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        
        if [ $((elapsed % 30)) -eq 0 ]; then
            log_info "Still waiting for services to be healthy... (${elapsed}s/${timeout}s)"
        fi
    done
    
    log_error "Services did not become healthy within $timeout seconds"
    return 1
}

# Initialize AI system
initialize_ai_system() {
    log_info "Initializing AI system..."
    
    # Wait a bit for the service to fully start
    sleep 10
    
    # Run initialization script inside the container
    if docker-compose exec -T proxy-core test -f ./scripts/init-ai-system.sh; then
        docker-compose exec -T proxy-core ./scripts/init-ai-system.sh
        log_success "AI system initialized"
    else
        log_warning "AI initialization script not found in container"
        
        # Try to initialize from host
        if [ -f "./scripts/init-ai-system.sh" ]; then
            REDIS_HOST=localhost ./scripts/init-ai-system.sh
        else
            log_warning "Could not initialize AI system automatically"
        fi
    fi
}

# Clean up old deployments
cleanup_deployments() {
    log_info "Cleaning up old deployments..."
    
    # Remove stopped containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    # Remove unused networks
    docker network prune -f
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    echo "🚀 AI Threat Detection System Deployment"
    echo "========================================"
    echo "Environment: $DEPLOYMENT_ENV"
    echo "Service: $SERVICE_NAME"
    echo "Image: $DOCKER_IMAGE:$DOCKER_TAG"
    echo
    
    check_prerequisites
    
    case $COMMAND in
        build)
            build_image
            ;;
        deploy)
            build_image
            deploy_service
            ;;
        start)
            start_service
            ;;
        stop)
            stop_service
            ;;
        restart)
            restart_service
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        health)
            check_health
            ;;
        cleanup)
            cleanup_deployments
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