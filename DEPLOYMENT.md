# Blackbook Docker Deployment Guide

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [SSL/TLS Setup](#ssltls-setup)
6. [Security](#security)
7. [Operations](#operations)
8. [Troubleshooting](#troubleshooting)
9. [Production Deployment](#production-deployment)

---

## Overview

The Blackbook Docker setup provides a secure, production-ready deployment of the cryptographic application with:

- **Isolated Services**: PostgreSQL database and Blackbook application in separate containers
- **Network Security**: Internal-only database access, HTTPS for application access
- **Unprivileged Users**: Both database and application run as non-root users
- **Resource Limits**: CPU and memory constraints for stability
- **Health Checks**: Automatic availability monitoring
- **Audit Logging**: Comprehensive database and application logging
- **Data Persistence**: Docker volumes for database durability

**Key Files**:
- `Dockerfile` - Multi-stage build (build + runtime)
- `docker-compose.yml` - Service orchestration and networking
- `config/postgres.conf` - PostgreSQL config (SSL, SCRAM, logging), loaded via `-c config_file`
- `config/pg_hba.conf` - Postgres auth rules (TLS-only, SCRAM; rejects plaintext)
- `config/blackbook.env` - Example env vars (copy to `./.env`)
- `scripts/01-blackbook-roles.sh` - Creates the least-privilege `blackbook_app` role on first boot
- `scripts/postgres-entrypoint.sh` - Installs Postgres TLS certs with correct perms
- `scripts/generate-postgres-certs.sh` - Generates the Postgres CA + server cert (run once)
- `scripts/generate-certificates.{sh,ps1}` - *Optional* certs for a reverse proxy only; the
  Blackbook **API** server auto-mints its own CA + cert (no manual step needed)

---

## Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                   Host Machine                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │        Docker Network: blackbook_network        │   │
│  │          (172.25.0.0/16, isolated)              │   │
│  │                                                  │   │
│  │  ┌──────────────────┐   ┌─────────────────────┐ │   │
│  │  │   PostgreSQL     │   │   Blackbook App     │ │   │
│  │  │   Container      │◄──┤   Container         │ │   │
│  │  │                  │   │                     │ │   │
│  │  │  :5432 (internal)│   │  :8443 (local HTTPS)├─┼───┼─► localhost:8443
│  │  │  unprivileged    │   │  unprivileged       │ │   │
│  │  │  user:999        │   │  user:1000          │ │   │
│  │  └──────────────────┘   └─────────────────────┘ │   │
│  │                                                  │   │
│  │  Data Volumes:                                   │   │
│  │  - blackbook_db_data (PostgreSQL)                │   │
│  │  - blackbook_data (master key, CA, certs, DEK)   │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### User Privileges

| Component | User | UID | Shell | Permissions |
|-----------|------|-----|-------|-------------|
| PostgreSQL | `postgres` | 999 | `/bin/false` | Read/Write DB only |
| Blackbook | `blackbook` | 1000 | `/usr/sbin/nologin` | Read/Write app only |
| Host | varies | varies | varies | Full access |

### Database Access Control

| User | Type | Scope | Privileges | Purpose |
|------|------|-------|------------|---------|
| `blackbook_admin` | Superuser | cluster | Super | Init / break-glass only — **not** used by the app |
| `blackbook_app` | Login role | own `blackbook_*` objects in the one DB | USAGE+CREATE on `public`; owns its tables. **No** createrole/createdb/replication/bypassrls | The application (connects over TLS) |
| `blackbook_backup` | Login role | `public` tables | SELECT only (optional, if `BACKUP_PASSWORD` set) | Read-only backups |
| `postgres` | System | system | Super | Database system |

---

## Quick Start

### Prerequisites

- Docker: >= 20.10
- Docker Compose: >= 2.0
- OpenSSL: for certificate generation
- Disk Space: >= 1GB for database + images
- Memory: >= 1GB available

### 1. Generate SSL/TLS Certificates

**Linux/macOS**:
```bash
# Make script executable
chmod +x scripts/generate-certificates.sh

# Generate certificates (self-signed for development)
./scripts/generate-certificates.sh

# Certificates created in: .certs/
```

**Windows (PowerShell)**:
```powershell
# Generate certificates
.\scripts\generate-certificates.ps1 -CertDir ".\.certs" -CertName "server"

# Certificates created in: .\.certs\
```

### 2. Configure Environment

```bash
# Copy configuration template
cp config/blackbook.env .env

# Edit .env with your settings
nano .env
```

**Important changes**:
- `DB_ADMIN_PASSWORD` - Change to strong password
- `DB_PASSWORD` - Change to strong password
- `BACKUP_PASSWORD` - Change to strong password
- `RUST_LOG` - Set to `info` for production

### 3. Build and Start Services

```bash
# Build Docker image
docker-compose build

# Start all services (creates and runs containers)
docker-compose up -d

# View service status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose stop

# Start services again
docker-compose start

# Remove all containers
docker-compose down

# Remove all data (WARNING: deletes database)
docker-compose down -v
```

### 4. Verify Services

```bash
# Check service health
docker-compose ps
# Both postgres and blackbook should show "healthy"

# Check logs
docker-compose logs postgres
docker-compose logs blackbook

# Test database connection
docker-compose exec postgres psql -U blackbook_admin -d blackbook -c "SELECT version();"

# Test application health (the /health endpoint is unauthenticated — no cert needed)
curl --cacert ca.crt https://localhost:8443/health
```

---

## Configuration

### Environment Variables

**File**: `config/blackbook.env`

Expected variables:
- `DB_ADMIN_PASSWORD` - PostgreSQL admin password
- `DB_PASSWORD` - Application database password
- `BACKUP_PASSWORD` - Backup user password
- `RUST_LOG` - Logging level (debug, info, warn, error)
- `BLACKBOOK_HTTPS_PORT` - HTTPS listen port (default: 8443)

### PostgreSQL Configuration

**File**: `config/postgres.conf`

Key settings:
- **Security**: SCRAM-SHA-256 password hashing, connection logging
- **Logging**: All statements logged for audit trail
- **Performance**: Tuned for 1GB shared buffers
- **WAL**: Write-Ahead Logging enabled for recovery

To customize:
1. Edit `config/postgres.conf`
2. Restart PostgreSQL: `docker-compose restart postgres`

### Database Initialization

**File**: `scripts/01-blackbook-roles.sh` (runs once, on a fresh data volume)

This shell hook creates the least-privilege `blackbook_app` login role (and, if
`BACKUP_PASSWORD` is set, a read-only `blackbook_backup` role), grants the app
`USAGE`+`CREATE` on `public`, and revokes `CONNECT` from `PUBLIC`. The Blackbook
server then creates all its `blackbook_*` tables at startup — **as `blackbook_app`,
which owns them** — via idempotent `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE …
ADD COLUMN IF NOT EXISTS` statements in `main.rs`.

To add custom bootstrap SQL: drop another `NN-name.sh`/`.sql` into `scripts/` and
mount it into `/docker-entrypoint-initdb.d/`. Verify the schema/ownership with:
`docker compose exec postgres psql -U blackbook_admin -d blackbook -c "\dt"`.

---

## SSL/TLS Setup

### How Blackbook manages its own certificates

Blackbook is a self-contained PKI. On first boot it generates a fresh CA and signs its own server certificate using rcgen; both are written into the `blackbook_data` volume. **No external certificate is required for the Blackbook server itself.** Clients authenticate using certs issued by that same CA.

To retrieve the CA certificate for use by the CLI:
```bash
docker cp blackbook-app:/opt/blackbook/data/ca.crt .
```

### Optional: reverse-proxy certificates

If you place an nginx or other TLS-terminating proxy in front of Blackbook you can generate self-signed development certs with the included scripts:

```bash
# Linux/macOS
./scripts/generate-certificates.sh   # writes to .certs/

# Windows PowerShell
.\scripts\generate-certificates.ps1 -CertDir ".\.certs" -CertName "server"
```

Creates:
- `.certs/server.crt` — Certificate (public key)
- `.certs/server.key` — Private key (keep secure, mode 0600)

For production reverse-proxy certs obtain them from a trusted CA (DigiCert, Let's Encrypt, your organisation's CA). The Blackbook server itself will continue to use its own internal CA regardless of what the proxy presents to external clients.

---

## Security

### Network Security

**Current Setup**:
- ✅ PostgreSQL not exposed to host (no port mapping)
- ✅ PostgreSQL only accessible from Blackbook container
- ✅ Blackbook accessible on localhost:8443 only (127.0.0.1)
- ✅ Encrypted communication via HTTPS
- ✅ Isolated Docker network (172.25.0.0/16)

**Accessing from Remote Host**:
```bash
# SSH tunnel (recommended)
ssh -L 8443:localhost:8443 user@host

# Then access via: https://localhost:8443

# Or update docker-compose.yml ports:
# ports:
#   - "8443:8443"  # Caution: exposes to all interfaces
```

### User Privilege Separation

**PostgreSQL**:
- Runs as `postgres` user (UID 999)
- Cannot execute system commands
- Limited to database operations only
- Cannot modify Docker configuration

**Blackbook**:
- Runs as `blackbook` user (UID 1000)
- Cannot read private keys (owned by system)
- Cannot modify database schema
- Cannot execute arbitrary commands

### Password Security

**Development Defaults** (in `config/blackbook.env`):
```
DB_ADMIN_PASSWORD=secure_default_password_change_me_in_production
DB_PASSWORD=secure_default_password_change_me_in_production
```

**Generate Strong Passwords**:
```bash
# Linux/macOS
openssl rand -base64 32

# Windows PowerShell
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).ToString())) | Select-Object -First 1 -ExpandProperty 0
```

**Update Passwords**:
1. Generate new password
2. Update `.env` file
3. Restart containers: `docker-compose restart`
4. Verify: `docker-compose logs postgres`

### Capability Dropping

Blackbook container drops all Linux capabilities except `NET_BIND_SERVICE`:
```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # Required for port 8443
```

This prevents:
- ✅ Container breakout
- ✅ System command execution
- ✅ Network sniffing
- ✅ File system access beyond Docker volumes

### Read-Only Filesystem

Blackbook container uses read-only root filesystem:
```yaml
read_only: true
tmpfs:
  - /tmp
  - /run
```

This prevents:
- ✅ Malicious file creation
- ✅ Configuration changes
- ✅ Persistence of attacks
- ✅ Unauthorized modifications

### Audit Logging

PostgreSQL logs all operations:
```bash
# View PostgreSQL logs
docker-compose logs postgres | grep LOG

# View application logs
docker-compose logs blackbook
```

Log storage:
- PostgreSQL: `/var/log/postgresql/` in container (ephemeral)
- Blackbook: stdout (Docker logs)

For persistent logs:
```bash
# Collect logs to file
docker-compose logs > blackbook.log

# Or configure log driver in docker-compose.yml
```

---

## Operations

### Monitoring

**Service Status**:
```bash
# Check if containers are running
docker-compose ps

# Check resource usage
docker stats

# Monitor in real-time
watch docker-compose ps
```

**Health Checks**:
```bash
# PostgreSQL health
docker-compose exec postgres pg_isready -U blackbook_admin

# Blackbook health
docker-compose exec blackbook /opt/blackbook/bin/blackbook health

# Automatic health: checks run every 30 seconds
docker-compose logs | grep -i health
```

### Backup and Restore

**Backup Database**:
```bash
# Create backup
docker-compose exec postgres pg_dump -U blackbook_admin blackbook > backup_$(date +%Y%m%d_%H%M%S).sql

# Compressed backup
docker-compose exec postgres pg_dump -U blackbook_admin blackbook | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

**Restore Database**:
```bash
# Restore from backup
docker-compose exec -T postgres psql -U blackbook_admin blackbook < backup_20260316_120000.sql

# From compressed backup
gunzip < backup_20260316_120000.sql.gz | docker-compose exec -T postgres psql -U blackbook_admin blackbook
```

**Backup Data Volume**:
```bash
# Create backup of volume
docker run --rm -v blackbook_db_data:/data -v $(pwd):/backup alpine tar czf /backup/db_backup.tar.gz /data

# Restore from backup
docker volume create blackbook_db_data_restored
docker run --rm -v blackbook_db_data_restored:/data -v $(pwd):/backup alpine tar xzf /backup/db_backup.tar.gz -C /data --strip-components=1
```

### Scaling

**Multiple Blackbook Instances** (with load balancer):
```yaml
services:
  blackbook:
    deploy:
      replicas: 3  # Run 3 instances

  # Add load balancer (nginx)
  nginx:
    image: nginx:latest
    ports:
      - "8443:8443"
    depends_on:
      - blackbook
```

### Updating

**Update Blackbook Version**:
```bash
# Pull latest code
git pull

# Rebuild image
docker-compose build --no-cache blackbook

# Restart service
docker-compose up -d blackbook

# Verify
docker-compose logs blackbook
```

**Update PostgreSQL Version**:
```bash
# WARNING: This requires database migration
# Backup first!
docker-compose exec postgres pg_dump -U blackbook_admin blackbook > backup.sql

# Update image in docker-compose.yml
# postgres:
#   image: postgres:16-alpine  # Updated version

# Stop and remove
docker-compose down

# Rebuild and start
docker-compose up -d

# Verify
docker-compose exec postgres psql -U blackbook_admin -c "SELECT version();"
```

---

## Troubleshooting

### Common Issues

**Services won't start**:
```bash
# Check Docker daemon
docker version

# Check logs
docker-compose logs

# Rebuild images
docker-compose build --no-cache

# Restart services
docker-compose down
docker-compose up -d
```

**Database connection failed**:
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Test connection
docker-compose exec postgres psql -U blackbook_admin -d blackbook -c "SELECT 1"

# Check environment variables
docker-compose config | grep -A 10 "postgres:"
```

**Certificate not found**:
Blackbook generates its own CA and server cert automatically on first start into the
`blackbook_data` volume. If certs are missing, the volume may have been wiped. Verify
the data volume is intact:
```bash
# Check data volume contents
docker-compose exec blackbook ls -la /opt/blackbook/data/

# If empty, the volume was lost — restart will re-initialize (new CA, new admin token).
docker-compose restart blackbook
```

**Permission denied errors**:
```bash
# Check file permissions
ls -la config/ scripts/

# Fix if needed
chmod 755 scripts/*.sh
chmod 644 config/* .dockerignore

# Check volume permissions
docker-compose exec postgres ls -la /var/lib/postgresql/
docker-compose exec blackbook ls -la /opt/blackbook/
```

**Port already in use**:
```bash
# Find process using port 8443
lsof -i :8443  # Linux/macOS
netstat -anob | findstr :8443  # Windows

# Or use different port
# Edit docker-compose.yml:
# ports:
#   - "127.0.0.1:9443:8443"
```

**High memory usage**:
```bash
# Check resource limits
docker-compose config | grep -A 10 "resources:"

# Update limits in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G  # Increase limit

# Restart
docker-compose restart
```

### Debug Mode

**Enable verbose logging**:
```bash
# Update .env
RUST_LOG=debug

# Restart
docker-compose restart blackbook

# View debug logs
docker-compose logs -f blackbook | grep -i debug
```

**Access container shell** (for investigation):
```bash
# PostgreSQL shell
docker-compose exec postgres psql -U blackbook_admin -d blackbook

# Or bash/sh
docker-compose exec postgres sh

# Blackbook container (read-only, limited)
docker-compose exec blackbook sh  # Fails due to read-only FS
```

**Inspect container state**:
```bash
# View network
docker network inspect blackbook_blackbook_network

# View volumes
docker volume inspect blackbook_db_data

# View image details
docker image inspect blackbook-blackbook_app
```

---

## Production Deployment

### Pre-Deployment Checklist

- [ ] Generate strong database passwords (32+ chars)
- [ ] Obtain SSL/TLS certificate from trusted CA
- [ ] Configure firewall (allow only 8443 from authorized IPs)
- [ ] Set up persistent storage (separate drive/mount)
- [ ] Enable database backups (daily or hourly)
- [ ] Configure monitoring and alerting
- [ ] Test disaster recovery procedures
- [ ] Document operational procedures
- [ ] Set up centralized logging
- [ ] Configure security scanning

### Security Hardening

**1. Update PostgreSQL Configuration**:
```bash
# Edit config/postgres.conf
# Set: ssl = on
# Set: password_encryption = 'scram-sha-256'
# Add pg_tls_require = on
```

**2. Network Isolation**:
```bash
# Remove localhost bind in production
# Add reverse proxy (nginx/HAProxy) if needed
# Change docker-compose.yml:
# ports:
#   - "reverse-proxy:8443:8443"
```

**3. Secrets Management**:
```bash
# Use Docker Secrets (Swarm mode) instead of .env
docker secret create db_admin_password -
# Paste password, press Ctrl+D

# Or use HashiCorp Vault, AWS Secrets Manager, etc.
```

**4. Monitoring Stack**:
```yaml
# Add to docker-compose.yml
prometheus:
  image: prom/prometheus
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml

grafana:
  image: grafana/grafana
  depends_on:
    - prometheus
```

**5. Automated Backups**:
```bash
# Create backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec -T postgres pg_dump -U blackbook_admin blackbook | gzip > "$BACKUP_DIR/blackbook_$DATE.sql.gz"
# Keep backups for 30 days
find "$BACKUP_DIR" -name "blackbook_*.sql.gz" -mtime +30 -delete
```

### Scaling for Production

**Docker Compose** (Single host):
- Suitable for: Dev, test, small production
- Limitations: Single point of failure

**Docker Swarm** (Multi-host):
```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml blackbook

# Scale service
docker service update --replicas 3 blackbook_blackbook
```

**Kubernetes** (Enterprise):
```bash
# Convert docker-compose to Kubernetes manifests
kompose convert -f docker-compose.yml -o kubernetes/

# Deploy
kubectl apply -f kubernetes/

# Scale
kubectl scale deployment blackbook --replicas=3
```

### Monitoring and Alerting

**Prometheus Metrics**:
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'blackbook'
    static_configs:
      - targets: ['localhost:9090']
```

**Alert Rules**:
- Service down (health check failed)
- Database full (>90% disk)
- High error rate (>1%)
- Connection pool exhausted
- Memory limit approaching
- Certificate expiring soon

---

## Reference

### Useful Commands

```bash
# Service Management
docker-compose up -d                    # Start all
docker-compose down                     # Stop all
docker-compose restart blackbook        # Restart one service
docker-compose ps                       # Status
docker-compose logs -f                  # Follow logs
docker-compose config                   # Show computed config

# Container Operations
docker-compose exec postgres psql ...    # Execute command
docker-compose exec postgres sh          # Interactive shell
docker stats                             # View resource usage
docker inspect <container>               # Detailed info

# Image Management
docker-compose build                    # Build images
docker-compose build --no-cache         # Rebuild from scratch
docker image ls                          # List images
docker image rm <image>                  # Remove image

# Volume Management
docker volume ls                         # List volumes
docker volume inspect <volume>           # Volume details
docker volume rm <volume>                # Remove volume
docker run -v <volume>:/data alpine ls   # Browse volume contents

# Network
docker network ls                        # List networks
docker network inspect <network>         # Network details
```

### File Locations

Inside containers:
- App binary: `/opt/blackbook/bin/blackbook`
- Config: `/opt/blackbook/config/`
- Certificates: `/opt/blackbook/certs/`
- Database data (PostgreSQL): `/var/lib/postgresql/data`
- Database logs: `/var/log/postgresql/`

On host:
- Docker config: `./docker-compose.yml`
- Application code: `./src/`
- Configuration: `./config/`
- Scripts: `./scripts/`
- Certificates: `./.certs/`
- Database backups: `./backups/` (create manually)

### Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/sql-security.html)
- [Rust Deployment Best Practices](https://doc.rust-lang.org/book/ch20-03-designing-the-multithreaded-web-server.html)

---

## Support

For issues or questions:

1. Check logs: `docker-compose logs`
2. Review troubleshooting section above
3. Check configuration: `docker-compose config`
4. Test connectivity: `docker-compose exec <service> <command>`
5. Review Docker documentation

---

**Last Updated**: March 16, 2026  
**Version**: 1.0  
**Status**: Production Ready ✅
