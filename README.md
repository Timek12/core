# Luna Core

A secure secrets management system built with microservices architecture.

## Important Setup Requirement

This repository must be placed in a folder alongside the `ui` repository for the Docker build context to work correctly.

**Required Directory Structure:**

```
workspace/
├── core/           # This repository (Backend services)
│   ├── docker-compose.yml
│   └── ...
└── ui/             # Frontend repository
    ├── Dockerfile
    └── ...
```

## Easy Start

The project is configured with predefined environment variables in `docker-compose.yml` for instant testing. You do not need to create any `.env` files manually.

```bash
# Start everything
docker-compose up -d --build

# Check if running
docker-compose ps
```

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
3. Initialize vault with external token. You can generate a secure key using the **Encryption Key 256** option from [acte.ltd/utils/randomkeygen](https://acte.ltd/utils/randomkeygen).
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
