# 🐳 DRAKBEN Docker Deployment

## Quick Start

### 1. Build the image:
```bash
docker build -t drakben:4.0 .
```

### 2. Run with Docker:
```bash
docker run -it --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/logs:/app/logs:rw \
  -p 4444:4444 \
  drakben:4.0
```

### 3. Run with Docker Compose:
```bash
# Development mode
docker-compose up -d

# Production mode with database
docker-compose --profile production up -d

# Interactive mode
docker-compose run --rm drakben
```

## Configuration

### Environment Variables

Create `.env` file:
```env
# API Keys
OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxx

# Database
DB_PASSWORD=secure_password_here

# Mode
DRAKBEN_MODE=production
```

### Volume Mounts

- `./config:/app/config:ro` - Configuration files (read-only)
- `./logs:/app/logs:rw` - Log files (read-write)
- `drakben_data:/app/data` - Persistent data

## Services

### drakben (Main Application)
- Port 4444: Reverse shell listener
- Port 8080: Web interface (optional)
- Resource limits: 2 CPU, 4GB RAM

### postgres (Database)
- Port 5432: PostgreSQL
- Default user: `drakben`
- Database: `drakben`

### redis (Cache)
- Port 6379: Redis
- Persistent storage enabled

## Security

### Best Practices:
1. **Non-root user**: Container runs as `drakben` user (UID 1000)
2. **Read-only config**: Configuration mounted read-only
3. **Network isolation**: Custom bridge network
4. **Resource limits**: CPU and memory constraints
5. **Security options**: `no-new-privileges` enabled

### Hardening:
```bash
# Run with security profile
docker run --security-opt=no-new-privileges:true \
           --cap-drop=ALL \
           --cap-add=NET_RAW \
           --cap-add=NET_ADMIN \
           drakben:4.0
```

## Networking

### Host Network (for full network access):
```bash
docker run -it --rm --network=host drakben:4.0
```

### Custom Network:
```bash
docker network create drakben_pentest
docker run -it --rm --network=drakben_pentest drakben:4.0
```

## Persistence

### Data Backup:
```bash
# Backup volumes
docker run --rm \
  -v drakben_data:/data \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/drakben_backup.tar.gz /data
```

### Data Restore:
```bash
# Restore volumes
docker run --rm \
  -v drakben_data:/data \
  -v $(pwd)/backup:/backup \
  alpine tar xzf /backup/drakben_backup.tar.gz -C /
```

## Troubleshooting

### Check logs:
```bash
docker logs drakben_main
docker-compose logs -f drakben
```

### Shell access:
```bash
docker exec -it drakben_main /bin/bash
docker-compose exec drakben /bin/bash
```

### Rebuild after changes:
```bash
docker-compose build --no-cache
docker-compose up -d --force-recreate
```

## Production Deployment

### Multi-stage build (optimized):
```dockerfile
# Build stage
FROM python:3.11 as builder
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# Production stage
FROM python:3.11-slim
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/*
...
```

### Health Monitoring:
```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' drakben_main

# Auto-restart on failure
docker update --restart=unless-stopped drakben_main
```

## Kubernetes Deployment (Optional)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: drakben
spec:
  replicas: 1
  selector:
    matchLabels:
      app: drakben
  template:
    metadata:
      labels:
        app: drakben
    spec:
      containers:
      - name: drakben
        image: drakben:4.0
        ports:
        - containerPort: 4444
        resources:
          limits:
            memory: "4Gi"
            cpu: "2000m"
```

## Performance Tuning

### Resource Limits:
```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 8G
    reservations:
      cpus: '2.0'
      memory: 4G
```

### Parallel Execution:
```bash
# Increase workers
docker run -e PARALLEL_WORKERS=8 drakben:4.0
```
