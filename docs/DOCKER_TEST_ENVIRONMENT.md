# Docker Test Environment Setup Guide

This guide covers how to prepare, upda## Development Workflow

### Build System
```bash
# Configure build (use presets)
cmake --preset=debug

# Build a specific target (Ninja generator)
cmake --build build --target cxxlang_test -- -j 36

# Run a single test by regex (matches the Debug config)
ctest -C Debug --output-on-failure -R '^cxxlang_test$'

# Run all tests in Debug
ctest -C Debug --output-on-failure
```

### CRITICAL: Database Migration Requirement

**⚠️ BBServer CANNOT start without database schema being initialized first**

The BBServer requires specific database tables (including `user_quota`, `cjj365_users`, etc.) to function. These are created by running database migrations via the `dbmate` service. 

**Always ensure migrations run BEFORE starting BBServer:**

```bash
# ❌ WRONG - Will fail with "Table 'user_quota' doesn't exist"
docker compose -f docker-compose.client-test.yml up -d bbserver

# ✅ CORRECT - Migrations first, then BBServer
docker compose -f docker-compose.client-test.yml --profile migration up dbmate
docker compose -f docker-compose.client-test.yml up -d bbserver
```ild the BBServer Docker test environment for client distribution and testing.

## Overview

The Docker test environment provides a complete, isolated BBServer setup with:
- **BBServer**: C++20 ACME certificate management system
- **MySQL 8.0**: Database with automatic schema migrations  
- **Redis 8.2**: Caching and session storage
- **Isolated Networking**: No conflicts with local services

## Prerequisites

### System Requirements
- Docker with Compose plugin (or legacy docker-compose)
- Ports 3307 and 8080 available on host machine
- At least 2GB available disk space

### Network Configuration
If behind a corporate firewall, configure Docker daemon proxy settings:

```bash
# Create systemd proxy configuration
sudo mkdir -p /etc/systemd/system/docker.service.d

# Add proxy settings
sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf > /dev/null << 'EOF'
[Service]
Environment="HTTP_PROXY=http://proxy-server:port"
Environment="HTTPS_PROXY=http://proxy-server:port"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
EOF

# Restart Docker
sudo systemctl daemon-reload
sudo systemctl restart docker
```

## Project Structure

```
bb/
├── apps/bbserver/
│   ├── config_dir_for_docker/          # Docker-specific configs (no secrets)
│   └── config_dir/                     # Development configs (contains secrets)
├── build/apps/bbserver/bbserver_debug  # Compiled binary
├── db/                                 # Database migrations
├── docker-compose.client-test.yml     # Docker orchestration
├── Dockerfile.runtime                 # BBServer container definition
└── scripts/
    ├── package-client-test.sh          # Create distribution packages
    └── start-test-env.sh               # Environment startup script
```

## Configuration Management

### Environment Variables Priority
The system uses this configuration priority order:
1. **Environment variables** (highest priority)
2. **Properties files** (.properties)  
3. **JSON templates** (with ${var} substitution)

### Key Configuration Files
- `mysql_config.json` + `mysql_config.develop.properties`
- `redis_config.json` + `redis_config.develop.properties`
- `web_server_config.json` (port 8081 → mapped to 8080)

### Docker-Specific Settings
Environment variables override properties files:
```bash
export MYSQL_HOST=mysql        # Docker service name
export MYSQL_USER=testuser     # Docker credentials  
export MYSQL_SECRET=testpass   # Docker credentials
export REDIS_HOST=redis        # Docker service name
```

## Development Workflow

### 1. Build BBServer Binary
```bash
# Configure and build project
cmake --preset debug
cmake --build build --target bbserver_debug -j

# Verify binary exists
ls -la build/apps/bbserver/bbserver_debug
```

### 2. Test Local Docker Environment
```bash
# Clean rebuild (recommended after code changes)
docker compose -f docker-compose.client-test.yml down -v --remove-orphans
docker compose -f docker-compose.client-test.yml build --no-cache

# Start services step-by-step
docker compose -f docker-compose.client-test.yml up -d mysql redis
sleep 20  # Wait for MySQL to initialize (increased from 15s)

# CRITICAL: Run database migrations BEFORE starting BBServer
docker compose -f docker-compose.client-test.yml --profile migration up dbmate

# Verify migrations applied successfully
docker compose -f docker-compose.client-test.yml exec mysql mysql -u testuser -ptestpass -D cjj365_test -e "SHOW TABLES LIKE 'user_quota';"

> **Heads-up:** If you cannot run `dbmate` (for example, in air-gapped client environments) and instead import `db/schema.sql` manually, make sure to seed the lookup tables that migrations normally populate. At a minimum the `markets` table must contain the `US` and `CN` rows, otherwise BBServer bootstrapping will fail when it tries to create the default admin user. You can seed them with:
>
> ```bash
> docker compose -f docker-compose.client-test.yml exec mysql mysql -u root -prootpass -D cjj365_test <<'SQL'
> INSERT INTO markets (id, name, currency, locale, tax_mode, is_active, signup_bonus_minor)
> VALUES
>   ('US', 'United States', 'USD', 'en-US', 'tax_excl', 1, 2000),
>   ('CN', 'China', 'CNY', 'zh-CN', 'tax_incl', 1, 2000)
> ON DUPLICATE KEY UPDATE
>   name = VALUES(name),
>   currency = VALUES(currency),
>   locale = VALUES(locale),
>   tax_mode = VALUES(tax_mode),
>   is_active = VALUES(is_active),
>   signup_bonus_minor = VALUES(signup_bonus_minor);
> SQL
> ```

# Start BBServer (only after migrations complete)
docker compose -f docker-compose.client-test.yml up -d bbserver

# Verify all services healthy
docker compose -f docker-compose.client-test.yml ps
```

### 3. Health Check Verification
```bash
# Test BBServer API
curl -s http://localhost:8080/health
# Expected: {"success":true,"data":{"status":"ok"...}}

# Test database connectivity
docker compose -f docker-compose.client-test.yml exec bbserver curl -s mysql:3306
# Should connect without timeout

# View logs for troubleshooting
docker compose -f docker-compose.client-test.yml logs bbserver --tail=20
```

## Client Distribution

### Package Creation
```bash
# Create distribution package (stored in not_in_git/packages/)
./scripts/package-client-test.sh

# Output: bbserver-client-test-YYYYMMDD-HHMMSS.tar.gz (~51MB)
```

### Package Contents
```
bbserver-client-test-*/
├── bbserver_debug                      # Compiled binary
├── config_dir/                         # Configuration files (no secrets)  
├── db/                                # Database migrations
├── docker-compose.client-test.yml     # Container orchestration
├── Dockerfile.runtime                 # Container definition
├── scripts/start-test-env.sh          # Startup automation
└── README.md                          # Client instructions
```

### Client Usage
```bash
# Client extracts and runs
tar -xzf bbserver-client-test-*.tar.gz
cd bbserver-client-test-*
./scripts/start-test-env.sh

# Access services
curl http://localhost:8080/health       # BBServer API
mysql -h localhost -P 3307 -u testuser -p  # Database (password: testpass)
```

## Updating and Rebuilding

### After Code Changes
1. **Rebuild BBServer binary**:
   ```bash
   cmake --build build --target bbserver_debug
   ```

2. **Update Docker containers** (CRITICAL: Follow migration sequence):
   ```bash
   # Stop BBServer first to prevent startup before migrations
   docker compose -f docker-compose.client-test.yml stop bbserver
   
   # Rebuild container
   docker compose -f docker-compose.client-test.yml build --no-cache bbserver
   
   # If database schema changed, run migrations first
   docker compose -f docker-compose.client-test.yml --profile migration up dbmate
   
   # Then start BBServer
   docker compose -f docker-compose.client-test.yml up -d bbserver
   ```

### After Configuration Changes
1. **Test configuration locally**:
   ```bash
   # Verify variable substitution works
   ./build/apps/bbserver/bbserver_debug -c apps/bbserver/config_dir_for_docker --profile develop --dry-run
   ```

2. **Rebuild containers**:
   ```bash
   docker compose -f docker-compose.client-test.yml down
   docker compose -f docker-compose.client-test.yml build --no-cache
   docker compose -f docker-compose.client-test.yml up -d
   ```

### After Database Schema Changes
1. **Create new migration**:
   ```bash
   # Add new .sql file to db/migrations/
   # Follow naming: YYYYMMDDHHMMSS_description.sql
   ```

2. **Test migration**:
   ```bash
   docker compose -f docker-compose.client-test.yml down -v  # Remove data
   docker compose -f docker-compose.client-test.yml up -d mysql
   sleep 15
   docker compose -f docker-compose.client-test.yml --profile migration up dbmate
   ```

## Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check what's using ports
lsof -i :3307  # MySQL port
lsof -i :8080  # BBServer port

# Modify docker-compose.yml if needed
ports:
  - "3308:3306"  # Use different host port
```

#### Library Dependencies
```bash
# Check missing libraries in container
docker compose -f docker-compose.client-test.yml exec bbserver ldd ./bbserver

# Add missing libraries to Dockerfile.runtime
RUN apt-get update && apt-get install -y \
    libmissing-library-name
```

#### Database Connection Timeout
```bash
# Verify container networking
docker compose -f docker-compose.client-test.yml exec bbserver nslookup mysql

# Check MySQL logs
docker compose -f docker-compose.client-test.yml logs mysql

# Verify environment variables
docker compose -f docker-compose.client-test.yml exec bbserver env | grep MYSQL
```

#### Missing Database Tables (e.g., "Table 'user_quota' doesn't exist")
```bash
# This indicates migrations haven't run - DO NOT start BBServer without migrations
# 1. Stop BBServer if running
docker compose -f docker-compose.client-test.yml stop bbserver

# 2. Check if migrations have run
docker compose -f docker-compose.client-test.yml exec mysql mysql -u testuser -ptestpass -D cjj365_test -e "SHOW TABLES;"

# 3. Run migrations if tables are missing
docker compose -f docker-compose.client-test.yml --profile migration up dbmate

# 4. Verify critical tables exist
docker compose -f docker-compose.client-test.yml exec mysql mysql -u testuser -ptestpass -D cjj365_test -e "SHOW TABLES LIKE 'user_quota';"

# 5. Start BBServer only after migrations complete
docker compose -f docker-compose.client-test.yml up -d bbserver
```

#### Network Issues with dbmate
```bash
# If dbmate fails with "network not found" error:
# Option 1: Clean up Docker networks completely
docker compose -f docker-compose.client-test.yml down -v --remove-orphans
docker system prune -f
docker compose -f docker-compose.client-test.yml up -d mysql redis
sleep 20
docker compose -f docker-compose.client-test.yml --profile migration up dbmate

# Option 2: Use simplified script that bypasses dbmate
./scripts/start-test-env-simple.sh

# Option 3: Apply schema directly (fallback)
docker compose -f docker-compose.client-test.yml exec -T mysql mysql -u root -prootpass -D cjj365_test < db/schema.sql
```

#### Configuration Issues
```bash
# Check configuration files in container
docker compose -f docker-compose.client-test.yml exec bbserver ls -la config-dir/

# Verify variable substitution
docker compose -f docker-compose.client-test.yml exec bbserver cat config-dir/mysql_config.json
```

### Clean Reset
```bash
# Complete environment reset
docker compose -f docker-compose.client-test.yml down -v --remove-orphans
docker system prune -f
docker compose -f docker-compose.client-test.yml build --no-cache
```

## Service Endpoints

| Service | Internal | External | Credentials |
|---------|----------|----------|-------------|
| BBServer | bbserver:8081 | localhost:8080 | - |
| MySQL | mysql:3306 | localhost:3307 | testuser/testpass |
| Redis | redis:6379 | (internal only) | - |

## Security Notes

- Uses `config_dir_for_docker` to exclude production secrets
- Default admin user: `jianglibo@hotmail.com` (password auto-generated)
- Test database credentials are hardcoded (not for production)
- No SSL/TLS in test environment (development only)

## Performance Tuning

### Resource Limits
Add to docker-compose.yml:
```yaml
services:
  bbserver:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
```

### Database Optimization
```yaml
mysql:
  command: --innodb-buffer-pool-size=256M --max-connections=50
```

## CI/CD Integration

### Automated Testing
```bash
#!/bin/bash
# test-docker-env.sh
set -e

# Build and test
cmake --build build --target bbserver_debug
docker compose -f docker-compose.client-test.yml down -v
docker compose -f docker-compose.client-test.yml build --no-cache
docker compose -f docker-compose.client-test.yml up -d

# Wait for health
sleep 30
curl -f http://localhost:8080/health

# Cleanup
docker compose -f docker-compose.client-test.yml down
```

### Package Validation
```bash
# Validate package completeness
./scripts/package-client-test.sh
tar -tzf not_in_git/packages/bbserver-client-test-*.tar.gz | grep -E "(bbserver_debug|docker-compose|README.md)"
```

---

## Quick Reference

**Start Environment (Automated)**: `./scripts/start-test-env.sh`  
**Start Environment (Simple/Reliable)**: `./scripts/start-test-env-simple.sh` *(avoids dbmate networking issues)*  
**Start Environment (Manual)**:
```bash
docker compose -f docker-compose.client-test.yml up -d mysql redis
sleep 20
docker compose -f docker-compose.client-test.yml --profile migration up dbmate
docker compose -f docker-compose.client-test.yml up -d bbserver
```
**Stop Environment**: `docker compose -f docker-compose.client-test.yml down`  
**Reset Environment**: `docker compose -f docker-compose.client-test.yml down -v --remove-orphans`  
**View Logs**: `docker compose -f docker-compose.client-test.yml logs -f bbserver`  
**Health Check**: `curl http://localhost:8080/health`  
**Create Package**: `./scripts/package-client-test.sh`  
**Run Migrations Only**: `docker compose -f docker-compose.client-test.yml --profile migration up dbmate`  

For issues or questions, refer to the main BB project documentation or contact the development team.