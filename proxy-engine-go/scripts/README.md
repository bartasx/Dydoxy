# AI Threat Detection System Scripts

This directory contains scripts for deploying, initializing, and managing the AI Threat Detection System.

## Scripts Overview

### 1. `init-ai-system.sh`
Initializes the AI threat detection system with default configurations, sample data, and Redis keys.

**Usage:**
```bash
./scripts/init-ai-system.sh
```

**Environment Variables:**
- `REDIS_HOST` - Redis host (default: localhost)
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_DB` - Redis database number (default: 0)
- `AI_MODELS_DIR` - Directory for AI models (default: ./models)
- `AI_DATA_DIR` - Directory for AI data (default: ./data)

**What it does:**
- Creates necessary directories for models and data
- Initializes Redis keys with AI system configuration
- Loads sample threat intelligence data
- Creates default behavioral profiles
- Sets up alert thresholds
- Creates sample training data

### 2. `deploy-ai-system.sh`
Handles deployment of the AI threat detection system using Docker and Docker Compose.

**Usage:**
```bash
# Build and deploy
./scripts/deploy-ai-system.sh deploy

# Just build the image
./scripts/deploy-ai-system.sh build

# Start services
./scripts/deploy-ai-system.sh start

# Stop services
./scripts/deploy-ai-system.sh stop

# Check status
./scripts/deploy-ai-system.sh status

# View logs
./scripts/deploy-ai-system.sh logs

# Check health
./scripts/deploy-ai-system.sh health
```

**Options:**
- `-e, --env ENV` - Deployment environment (development, staging, production)
- `-t, --tag TAG` - Docker image tag
- `-s, --service NAME` - Service name

**Environment Variables:**
- `DEPLOYMENT_ENV` - Deployment environment
- `DOCKER_IMAGE` - Docker image name
- `DOCKER_TAG` - Docker image tag
- `SERVICE_NAME` - Service name
- `HEALTH_CHECK_TIMEOUT` - Health check timeout in seconds

### 3. `migrate-ai-database.sh`
Manages database migrations for the AI threat detection system.

**Usage:**
```bash
# Run migrations
./scripts/migrate-ai-database.sh migrate

# Check migration status
./scripts/migrate-ai-database.sh status

# Create backup
./scripts/migrate-ai-database.sh backup

# Rollback to previous version
./scripts/migrate-ai-database.sh rollback

# Reset database (WARNING: destructive)
./scripts/migrate-ai-database.sh reset
```

**Options:**
- `-h, --host HOST` - Redis host
- `-p, --port PORT` - Redis port
- `-d, --db DB` - Redis database
- `-v, --version VERSION` - Migration version
- `-b, --backup-dir DIR` - Backup directory

## Quick Start Guide

### 1. Initial Setup

First, make sure you have Redis running:
```bash
# Using Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Or using your system's Redis
redis-server
```

### 2. Initialize the AI System

```bash
# Initialize with default settings
./scripts/init-ai-system.sh

# Or with custom Redis settings
REDIS_HOST=localhost REDIS_PORT=6379 ./scripts/init-ai-system.sh
```

### 3. Run Database Migrations

```bash
# Check current migration status
./scripts/migrate-ai-database.sh status

# Run all migrations
./scripts/migrate-ai-database.sh migrate
```

### 4. Deploy the System

```bash
# For development
./scripts/deploy-ai-system.sh -e development deploy

# For production
./scripts/deploy-ai-system.sh -e production deploy
```

### 5. Verify Deployment

```bash
# Check service status
./scripts/deploy-ai-system.sh status

# Check health
./scripts/deploy-ai-system.sh health

# View logs
./scripts/deploy-ai-system.sh logs
```

## Migration Versions

The database migration system supports the following versions:

- **v1**: Initial AI system setup
  - Basic system configuration
  - Default model configurations
  
- **v2**: Enhanced threat intelligence
  - Threat intelligence providers
  - Cache configuration
  
- **v3**: Advanced metrics and alerting
  - Metrics collection configuration
  - Default metric definitions
  - Alerting configuration and channels
  
- **v4**: Behavioral analysis enhancements
  - Enhanced behavioral profile templates
  - Anomaly detection configuration

## Configuration

### Environment Variables

The scripts support various environment variables for configuration:

#### Redis Configuration
```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_DB=0
```

#### AI System Configuration
```bash
export AI_MODELS_DIR=./models
export AI_DATA_DIR=./data
export AI_THREAT_DETECTION_ENABLED=true
export AI_CONFIDENCE_THRESHOLD=0.7
```

#### Deployment Configuration
```bash
export DEPLOYMENT_ENV=production
export DOCKER_IMAGE=dydoxy/proxy-core
export DOCKER_TAG=latest
export SERVICE_NAME=proxy-core
```

### Docker Compose Configuration

The deployment script automatically generates `docker-compose.yml` files based on the environment:

- **Development**: Basic setup with Redis and proxy-core
- **Staging**: Similar to development with additional monitoring
- **Production**: Includes Nginx reverse proxy and SSL configuration

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```bash
   # Check if Redis is running
   redis-cli ping
   
   # Check Redis logs
   docker logs redis
   ```

2. **Permission Denied**
   ```bash
   # Make scripts executable
   chmod +x scripts/*.sh
   ```

3. **Docker Issues**
   ```bash
   # Check Docker daemon
   docker info
   
   # Clean up Docker resources
   ./scripts/deploy-ai-system.sh cleanup
   ```

4. **Migration Failures**
   ```bash
   # Check migration status
   ./scripts/migrate-ai-database.sh status
   
   # Create backup before retrying
   ./scripts/migrate-ai-database.sh backup
   
   # Reset and start over (if needed)
   ./scripts/migrate-ai-database.sh reset
   ```

### Health Checks

The system provides several health check endpoints:

- `http://localhost:9090/health` - Main service health
- `http://localhost:9090/api/v1/ai/health` - AI system health
- `http://localhost:9090/api/v1/ai/metrics` - AI metrics

### Logs

View logs using:
```bash
# All services
./scripts/deploy-ai-system.sh logs

# Specific service
docker-compose logs -f proxy-core

# Redis logs
docker-compose logs -f redis
```

## Security Considerations

1. **Redis Security**
   - Use authentication in production
   - Configure firewall rules
   - Use TLS encryption

2. **Docker Security**
   - Run containers as non-root user
   - Use official base images
   - Regularly update images

3. **API Security**
   - Enable authentication
   - Use HTTPS in production
   - Implement rate limiting

## Backup and Recovery

### Creating Backups

```bash
# Create manual backup
./scripts/migrate-ai-database.sh backup

# Automated backup (add to cron)
0 2 * * * /path/to/scripts/migrate-ai-database.sh backup
```

### Restoring from Backup

```bash
# List available backups
ls -la ./backups/

# Restore from backup
./scripts/migrate-ai-database.sh restore
```

## Monitoring

The system provides comprehensive monitoring through:

1. **Metrics Collection**
   - Prometheus-compatible metrics
   - Custom AI-specific metrics
   - System performance metrics

2. **Health Monitoring**
   - Component health checks
   - Automated alerting
   - Performance thresholds

3. **Logging**
   - Structured JSON logging
   - Configurable log levels
   - Log aggregation support

## Support

For issues or questions:

1. Check the logs first
2. Verify configuration
3. Test Redis connectivity
4. Check Docker status
5. Review migration status

The scripts include detailed error messages and suggestions for common issues.