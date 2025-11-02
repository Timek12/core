# Luna Core

A secure secrets management system built with microservices architecture.

## What's Inside

- **Security Service** (port 8001) - User authentication & JWT tokens
- **Server Service** (port 8000) - API gateway & business logic
- **Storage Service** (port 8002) - Database & encrypted secrets storage
- **UI** (port 3000) - React web interface

## Quick Start

```bash
# Start everything
docker-compose up -d --build

# Check if running
docker-compose ps

# View logs
docker-compose logs -f
```

## First Time Setup

1. Visit `http://localhost:3000`
2. Login as admin: `admin@luna.com` / `Admin123@`
3. Initialize vault with external token
4. Unseal vault to access secrets

## Default Users

| Email             | Password  | Role  |
| ----------------- | --------- | ----- |
| admin@luna.com    | Admin123@ | admin |
| user1@example.com | User123@  | user  |

## Services

- Frontend: http://localhost:3000
- Server API: http://localhost:8000
- Security API: http://localhost:8001
- Storage API: http://localhost:8002 (internal)

## Tech Stack

- **Backend**: Python 3.11, FastAPI
- **Databases**: PostgreSQL (2 instances)
- **Cache**: Redis
- **Frontend**: React, TypeScript, Vite
- **Deployment**: Docker Compose, Kubernetes (Helm charts)

## More Info

See individual service READMEs:

- [Security Service](./security/README.md)
- [Server Service](./server/README.md)
- [Storage Service](./storage/README.md)
