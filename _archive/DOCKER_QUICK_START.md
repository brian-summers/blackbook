# Blackbook Docker Quick Start Guide

## 5-Minute Setup

### Step 1: Generate SSL Certificates

**Windows (PowerShell)**:
```powershell
.\scripts\generate-certificates.ps1
```

**Linux/macOS**:
```bash
chmod +x scripts/generate-certificates.sh
./scripts/generate-certificates.sh
```

✅ Certificates created in `.certs/` directory

### Step 2: Configure Environment

```bash
# Copy configuration template (already in ./config/blackbook.env)
# Review and customize if needed, especially passwords:
cat config/blackbook.env
```

### Step 3: Build and Start

```bash
# Build Docker images
docker-compose build

# Start all services (PostgreSQL + Blackbook)
docker-compose up -d

# Wait for health checks to pass (~10 seconds)
docker-compose ps

# View logs to verify startup
docker-compose logs
```

### Step 4: Verify Status

```bash
# Check service health
docker-compose ps

# Test database
docker-compose exec postgres psql -U blackbook_admin -d blackbook -c "SELECT version();"

# Test application
curl --insecure https://localhost:8443/health
```

✅ **Services are running!**

---

## Common Commands

### View Logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs postgresql
docker-compose logs blackbook

# Follow logs (real-time)
docker-compose logs -f

# Last N lines
docker-compose logs --tail=50
```

### Stop/Start Services
```bash
# Stop all (data persisted)
docker-compose stop

# Start again
docker-compose start

# Restart specific service
docker-compose restart blackbook

# Stop and remove containers (data persisted)
docker-compose down

# Stop and delete everything (WARNING: loses data)
docker-compose down -v
```

### Access Services
```bash
# PostgreSQL shell
docker-compose exec postgres psql -U blackbook_admin -d blackbook

# Run SQL query
docker-compose exec postgres psql -U blackbook_admin -d blackbook -c "SELECT * FROM secrets;"

# Run Blackbook commands
docker-compose exec blackbook /opt/blackbook/bin/blackbook --help
docker-compose exec blackbook /opt/blackbook/bin/blackbook health
```

### Backup Database
```bash
# Create backup
docker-compose exec postgres pg_dump -U blackbook_admin blackbook > backup.sql

# Compressed backup
docker-compose exec postgres pg_dump -U blackbook_admin blackbook | gzip > backup_$(date +%Y%m%d).sql.gz

# List backups
ls -lh backup*.sql*
```

### View Resource Usage
```bash
# Show memory/CPU usage
docker stats

# Specific container
docker stats blackbook-app
docker stats blackbook-postgres
```

---

## Architecture Overview

```
Host (127.0.0.1:8443)
        ↓ HTTPS
    ┌───────┐
    │ Nginx │  (optional reverse proxy)
    └───┬───┘
        ↓
    ┌─────────────────────────────────────────┐
    │    Docker Network (blackbook_network)   │
    │    Subnet: 172.25.0.0/16                │
    │                                         │
    │  ┌──────────┐      ┌──────────────┐    │
    │  │postgresql│ ◄─── │  blackbook   │    │
    │  │:5432     │      │  :8443       │    │
    │  │(internal)│      │  (container) │    │
    │  └──────────┘      └──────────────┘    │
    │   ↓volumes          ↓volumes            │
    │   db_data           certs               │
    └─────────────────────────────────────────┘
```

### Key Characteristics

- **PostgreSQL**: Only accessible from Blackbook container (no host port)
- **Blackbook**: Accessible via HTTPS on localhost:8443
- **Isolated Network**: Internal Docker network, separate from host
- **Unprivileged Users**: Both services run as limited-privilege users
- **Data Persistence**: Database data saved in Docker volumes
- **Self-Signed HTTPS**: Development certificates in `.certs/` directory

---

## Security Features

✅ **Implemented**:
- Certificate-based HTTPS encryption
- Internal-only database (no port exposure)
- Unprivileged user execution (UID 1000/999)
- Read-only root filesystem
- Dropped Linux capabilities
- Password-protected database
- Audit logging
- Resource limits (CPU/memory)
- Health checks
- SCRAM-SHA-256 password hashing

---

## Troubleshooting

### Services won't start
```bash
# Check if Docker is running
docker version

# Rebuild from scratch
docker-compose build --no-cache

# Check detailed logs
docker-compose logs | tail -50

# Restart
docker-compose down
docker-compose up -d
```

### Can't connect to database
```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Test connection
docker-compose exec postgres psql -U blackbook_admin -d blackbook -c "SELECT 1"

# Check environment variables
docker-compose config | grep -A 5 "environment:"
```

### HTTPS certificate issues
```bash
# Verify certificates exist
ls -la .certs/

# Regenerate if needed
./scripts/generate-certificates.sh

# Restart application
docker-compose restart blackbook
```

### Port already in use
```bash
# Find what's using port 8443
# Windows:
netstat -anob | findstr :8443

# Linux/macOS:
lsof -i :8443

# Choose different port in docker-compose.yml:
# ports:
#   - "127.0.0.1:9443:8443"
```

### High memory/CPU usage
```bash
# Check resource usage
docker stats

# Update limits in docker-compose.yml
# deploy:
#   resources:
#     limits:
#       memory: 1G
#       cpus: '2'

# Restart
docker-compose restart
```

---

## Environment Variables

**File**: `config/blackbook.env`

**Important variables**:
- `DB_ADMIN_PASSWORD` - PostgreSQL admin password
- `DB_PASSWORD` - Application database password
- `RUST_LOG` - Logging level (info/debug/warn/error)
- `BLACKBOOK_HTTPS_PORT` - HTTPS port (default: 8443)

**Change passwords**:
1. Generate new password: `openssl rand -base64 32`
2. Update `config/blackbook.env`
3. Restart: `docker-compose restart`

---

## Production Deployment

### Before Going Live

1. **Update all passwords**:
   ```bash
   openssl rand -base64 32  # Generate strong password
   # Update in config/blackbook.env
   ```

2. **Get proper SSL/TLS certificate**:
   - From trusted CA (DigiCert, Let's Encrypt, etc.)
   - Save as `.certs/server.crt` and `.certs/server.key`

3. **Enable access logs**:
   - Add reverse proxy (nginx/HAProxy)
   - Configure monitoring

4. **Test backup/restore**:
   ```bash
   docker-compose exec postgres pg_dump -U blackbook_admin blackbook > test_backup.sql
   # Verify backup can be restored
   ```

5. **Set resource limits**:
   - Adjust memory/CPU in docker-compose.yml
   - Based on expected workload

6. **Configure monitoring**:
   - Set up health check scripts
   - Alert on service failure
   - Monitor disk space, memory, CPU

### Deployment Options

**Single Host** (Current setup):
- Suitable for: Small production, staging
- Limitations: Single point of failure

**Multiple Hosts** (Swarm/Kubernetes):
- For: High availability, scaling
- Requires: Docker Swarm or Kubernetes cluster

See `DOCKER_DEPLOYMENT.md` for detailed production guide.

---

## File Structure

```
blackbook-docker/source.rs/blackbook/
├── Dockerfile                    # Multi-stage build
├── docker-compose.yml            # Service orchestration
├── .dockerignore                 # Build optimization
├── config/
│   ├── postgres.conf             # PostgreSQL configuration
│   └── blackbook.env             # Environment variables
├── scripts/
│   ├── generate-certificates.sh  # Certificate generation (Linux/Mac)
│   ├── generate-certificates.ps1 # Certificate generation (Windows)
│   └── 01-init-postgres.sql      # Database initialization
├── src/
│   ├── main.rs                   # CLI & database
│   └── blackbook_core.rs         # Cryptographic library
├── DOCKER_DEPLOYMENT.md          # Full documentation
└── DOCKER_QUICK_START.md         # This file
```

---

## Performance Tips

- **Build caching**: First build ~60s, subsequent builds <5s (if no code changes)
- **Database**: SSD recommended for best performance
- **Memory**: Minimum 1GB, 2GB+ recommended
- **Network**: Local only (no internet overhead)
- **Resource monitors**: Use `docker stats` to profile

---

## Next Steps

1. **Quick Start**: Follow 5-minute setup above
2. **Configuration**: Review `config/blackbook.env`
3. **Security**: Read `DOCKER_DEPLOYMENT.md` Security section
4. **Operations**: See `DOCKER_DEPLOYMENT.md` Operations section
5. **Production**: See `DOCKER_DEPLOYMENT.md` Production Deployment

---

## Support

For issues or questions:

1. Check logs: `docker-compose logs`
2. Review troubleshooting above
3. See full documentation: `DOCKER_DEPLOYMENT.md`
4. Verify setup: `docker-compose ps`

---

## Related Documentation

- **Full Guide**: [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
- **Blackbook**: [README.md](README.md)
- **Architecture**: [FRAMEWORK.md](FRAMEWORK.md)
- **Python→Rust Migration**: [TRANSFORMATION.md](TRANSFORMATION.md)
- **Code Examples**: [BLACKBOOK_CORE_EXAMPLES.md](BLACKBOOK_CORE_EXAMPLES.md)
- **All Documentation**: [INDEX.md](INDEX.md)

---

**Quick Reference Card**: Print this out!

```
═══════════════════════════════════════════════════════════════
                   BLACKBOOK DOCKER COMMANDS
═══════════════════════════════════════════════════════════════
Build & Start:
  docker-compose build              # Build images
  docker-compose up -d              # Start services
  docker-compose ps                 # Check status

Logs & Debugging:
  docker-compose logs               # View all logs
  docker-compose logs -f            # Follow logs
  docker-compose logs blackbook     # Specific service

Stop & Manage:
  docker-compose stop               # Stop services
  docker-compose start              # Start services
  docker-compose restart            # Restart services
  docker-compose down               # Stop & remove containers

Access Services:
  docker-compose exec postgres psql # PostgreSQL shell
  docker-compose exec blackbook sh  # Blackbook shell

Backup:
  docker-compose exec postgres pg_dump -U blackbook_admin blackbook > backup.sql

Resource Usage:
  docker stats                      # Monitor CPU/Memory

═══════════════════════════════════════════════════════════════
```

---

**Version**: 1.0  
**Last Updated**: March 16, 2026  
**Status**: Production Ready ✅
