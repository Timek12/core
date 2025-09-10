# LunaGuard Storage Service

The LunaGuard Storage Service is responsible for database provisioning and schema management within the LunaGuard platform.

## Overview

This service handles database schema creation and management, while the security service continues to handle all database operations directly. It provides a clean separation between provisioning (infrastructure) and operations (business logic).

## Architecture

- **Storage Service**: Database provisioning, schema creation, migrations
- **Security Service**: All database operations, CRUD, business logic, schema verification
- **Schema Management**: Single SQL file (`schema.sql`) for maintainable schema definitions

## Features

- **Centralized Schema**: All database schema defined in `schema.sql` file
- **Database Provisioning**: Table creation and indexing from SQL file
- **Schema Verification**: Security service verifies tables exist on startup
- **Health Monitoring**: Database connectivity checks
- **Connection Pooling**: Efficient database connections

## Project Structure

```
lunaguard-storage/
├── main.py              # FastAPI application
├── schema.sql           # Complete database schema definition
├── requirements.txt     # Python dependencies
├── Dockerfile          # Container configuration
├── .env.example        # Environment template
└── README.md           # This file
```

## API Endpoints

### Provisioning

- `POST /provision/database` - Create database schema from schema.sql
- `POST /provision/migrate` - Run migrations (future)
- `GET /provision/status` - Check provisioning status

### Health & Status

- `GET /health` - Service health check
- `GET /` - Root endpoint with service info

## Installation & Setup

### Prerequisites

- Python 3.11+
- PostgreSQL 12+
- pip

### Local Development

1. **Setup**:

   ```bash
   cd lunaguard-storage
   cp .env.example .env
   # Edit .env with your database configuration
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Start the service**:
   ```bash
   python main.py
   ```

The service will be available at `http://localhost:8002`

## Configuration

### Environment Variables

- `DB_HOST` - Database host (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_NAME` - Database name (default: lunaguard)
- `DB_USER` - Database user (default: postgres)
- `DB_PASSWORD` - Database password (default: password)
- `HOST` - Server host (default: 0.0.0.0)
- `PORT` - Server port (default: 8002)
- `DEBUG` - Debug mode (default: false)

## Workflow

### 1. Database Provisioning (One-time)

```bash
# Start storage service
python main.py

# Provision database schema
curl -X POST http://localhost:8002/provision/database
```

### 2. Security Service Operation

```bash
# Security service starts up
# - Connects to database
# - Verifies required tables exist
# - Operates normally if schema is present
# - Fails with clear error if schema missing
```

### 3. Schema Management

- **Edit Schema**: Modify `schema.sql` file
- **Apply Changes**: Call `/provision/database` endpoint
- **Version Control**: Track schema changes in git

## Integration

The security service no longer calls the storage service automatically. Instead:

1. **Security Service**: Assumes database schema exists
2. **Schema Verification**: Checks required tables on startup
3. **Manual Provisioning**: Run storage service separately to provision schema
4. **Clear Errors**: Security service provides clear error if schema missing

### Deployment Workflow

```bash
# 1. Deploy storage service
docker run -p 8002:8002 lunaguard-storage

# 2. Provision database (once)
curl -X POST http://localhost:8002/provision/database

# 3. Deploy security service (connects directly to DB)
docker run -p 8080:8080 lunaguard-security
```

```go
// Security service calls storage service for provisioning
resp, err := http.Post("http://lunaguard-storage:8002/provision/database", "", nil)
```

After provisioning, the security service connects directly to the database for all operations.

## License

Part of the LunaGuard platform - see main project LICENSE.
