# Production Deployment Guide

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone <repository-url>
cd Python.PHP.Sec.Scan

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 cli.py --init-db
```

### 2. Configuration

```bash
# Copy example configuration
cp config.yaml.example config.yaml
cp .env.example .env

# Edit configuration
vi config.yaml

# Or use environment variables
vi .env
```

### 3. Run Scan

```bash
# CLI scan
python3 cli.py scan --dir /path/to/php/project

# Start API server
python3 -m api.app

# Or with uvicorn
uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 4
```

## Architecture

### Core Components

**core/** directory structure:
- `config.py` - Configuration management
- `exceptions.py` - Custom exceptions
- `logger.py` - Structured logging
- `validators.py` - Input validation
- `detection_engine.py` - Vulnerability detection rules
- `rate_limiter.py` - Rate limiting & throttling
- `monitoring.py` - Metrics & health checks

### Configuration Priority

1. Command-line arguments
2. Configuration file (`config.yaml`)
3. Environment variables (`.env`)
4. Default values

### Logging

**Structured JSON logging:**
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "INFO",
  "logger": "php-security-scanner.scanner",
  "message": "Scan completed",
  "module": "scanner",
  "extra": {
    "scan_id": "abc123",
    "files_scanned": 150,
    "vulnerabilities": 5
  }
}
```

**Text logging (development):**
```
2025-01-15 10:30:00 - scanner - INFO - Scan completed
```

## Production Setup

### Docker Deployment

```bash
# Build image
docker build -t php-security-scanner:latest .

# Run container
docker run -d \
  --name scanner \
  -p 8000:8000 \
  -v /path/to/scan:/data \
  -v /path/to/config:/config \
  -e CONFIG_PATH=/config/config.yaml \
  php-security-scanner:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  scanner:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
      - ./config.yaml:/app/config.yaml
    environment:
      - LOG_LEVEL=INFO
      - DATABASE_URL=postgresql://user:pass@db/scanner
    depends_on:
      - db
      - redis

  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=scanner
      - POSTGRES_USER=scanner
      - POSTGRES_PASSWORD=secret
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redisdata:/data

volumes:
  pgdata:
  redisdata:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: php-security-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: scanner
  template:
    metadata:
      labels:
        app: scanner
    spec:
      containers:
      - name: scanner
        image: php-security-scanner:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: scanner-secrets
              key: database-url
        - name: REDIS_URL
          value: redis://redis-service:6379/0
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## API Usage

### Authentication

```bash
# TODO: Add API key authentication
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/scan
```

### Endpoints

**Create Scan:**
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "/path/to/php/project",
    "vulnerability_types": ["sql_injection", "xss"],
    "max_workers": 16,
    "use_cache": true
  }'
```

**Get Scan Status:**
```bash
curl http://localhost:8000/api/v1/scan/{scan_id}/status
```

**Get Results:**
```bash
curl http://localhost:8000/api/v1/scan/{scan_id}/results
```

**Health Check:**
```bash
curl http://localhost:8000/api/v1/health
```

**Metrics:**
```bash
curl http://localhost:8000/api/v1/metrics
```

## Monitoring

### Metrics

The scanner exposes metrics in JSON format at `/api/v1/metrics`:

```json
{
  "counters": {
    "scans_total": 150,
    "vulnerabilities_found_total": 450
  },
  "gauges": {
    "active_scans": 3,
    "cache_size_bytes": 524288000
  },
  "histograms": {
    "scan_duration_seconds": {
      "count": 150,
      "avg": 45.2,
      "p95": 120.5,
      "p99": 180.3
    }
  }
}
```

### Health Checks

```bash
# Overall health
curl http://localhost:8000/api/v1/health

# Response
{
  "overall_status": "healthy",
  "checks": {
    "cache": {"status": "healthy"},
    "database": {"status": "healthy"}
  }
}
```

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'php-scanner'
    static_configs:
      - targets: ['scanner:8000']
    metrics_path: '/api/v1/metrics'
```

### Grafana Dashboard

Import dashboard ID: `XXXXX` (TODO)

**Key Metrics:**
- Scans per minute
- Vulnerabilities found
- Scan duration (p50, p95, p99)
- Cache hit rate
- System resources (CPU, memory)

## Performance Tuning

### Worker Configuration

```yaml
performance:
  max_workers: 32  # Adjust based on CPU cores
  use_adaptive_workers: true  # Auto-adjust based on load
```

**Guidelines:**
- CPU-bound: `max_workers = CPU_cores * 2`
- IO-bound: `max_workers = CPU_cores * 4`
- Large files: Reduce workers to avoid memory issues

### Cache Optimization

```yaml
cache:
  backend: redis  # Faster than disk for distributed setups
  size_limit: 2147483648  # 2GB
  ttl: 86400  # Adjust based on code change frequency
```

### Database Optimization

```yaml
database:
  pool_size: 10  # Increase for high concurrency
  max_overflow: 20
```

For PostgreSQL:
```sql
-- Increase connection limit
ALTER SYSTEM SET max_connections = 200;

-- Add indexes
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id);
```

## Security Considerations

### API Security

1. **Rate Limiting**: Enabled by default (100 req/min)
2. **Authentication**: TODO - Implement API keys
3. **CORS**: Configure allowed origins in `config.yaml`
4. **HTTPS**: Use reverse proxy (nginx/traefik)

### File Access

- Scanner validates all file paths
- Prevents path traversal attacks
- Respects `exclude_patterns` configuration

### Resource Limits

```yaml
scan:
  max_file_size: 10485760  # Skip files > 10MB
  timeout_per_file: 30     # Prevent hung scans
```

## Troubleshooting

### High Memory Usage

```bash
# Check system metrics
curl http://localhost:8000/api/v1/metrics

# Reduce workers
export MAX_WORKERS=8

# Reduce cache size
export CACHE_SIZE_LIMIT=536870912  # 512MB
```

### Slow Scans

```bash
# Enable profiling
LOG_LEVEL=DEBUG python3 cli.py scan --dir /path

# Check cache hit rate
curl http://localhost:8000/api/v1/metrics | jq '.gauges.cache_hit_rate'

# Increase workers
MAX_WORKERS=64 python3 cli.py scan --dir /path
```

### Database Errors

```bash
# Check connection
python3 -c "from db.connection import get_session; session = get_session().__enter__(); print('OK')"

# Run migrations
alembic upgrade head

# Reset database
rm scanner.db
python3 cli.py --init-db
```

## Maintenance

### Backup

```bash
# Database
pg_dump scanner > backup.sql

# Cache (if important)
redis-cli SAVE

# Configuration
tar czf config-backup.tar.gz config.yaml .env
```

### Updates

```bash
# Pull latest code
git pull

# Update dependencies
pip install -U -r requirements.txt

# Run migrations
alembic upgrade head

# Restart service
systemctl restart php-scanner
```

### Log Rotation

```bash
# /etc/logrotate.d/php-scanner
/var/log/php-scanner/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 644 scanner scanner
    postrotate
        systemctl reload php-scanner
    endscript
}
```

## Support

- GitHub Issues: https://github.com/your-org/php-security-scanner/issues
- Documentation: https://docs.your-org.com/php-scanner
- Email: security@your-org.com
