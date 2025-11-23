# Server Service

API gateway and business logic layer. Orchestrates communication between UI, Security, and Storage services.

## What It Does

- Vault initialization & unsealing
- Data encryption/decryption (AES-GCM + DEK)
- Master key management in Redis
- Crypto operations (key derivation, encryption)
- Admin endpoints for managing all data

## Dependencies

- **Security Service** - Validates JWT tokens
- **Storage Service** - Persists encrypted data
- **Redis** - Caches master key (with TTL)

## Key Architecture

**Encryption Layers:**

1. Root Key (from external token) → decrypts Master Key
2. Master Key (cached in Redis) → decrypts DEKs
3. DEK (per data item) → encrypts actual data value

**Vault States:**

- `sealed` - Master key not in memory, data inaccessible
- `unsealed` - Master key cached, data can be encrypted/decrypted

## Endpoints

**Vault Management:**

- `POST /api/vault/init` - Initialize vault (one-time)
- `POST /api/vault/unseal` - Unseal with external token
- `POST /api/vault/seal` - Clear master key from cache
- `GET /api/vault/status` - Check vault state

**Data (User):**

- `GET /api/data` - List my data
- `POST /api/data` - Create new data
- `PUT /api/data/{id}` - Update data
- `DELETE /api/data/{id}` - Delete data

**Admin:**

- `GET /api/admin/data` - View all users' data
- `GET /api/admin/secrets/user/{id}` - Secrets for specific user
- `DELETE /api/admin/secrets/{id}` - Delete any secret

## Crypto Service

Uses `cryptography` library:

- **AES-GCM** - Authenticated encryption (256-bit keys)
- **PBKDF2-HMAC-SHA256** - Key derivation (600k iterations)
- **HKDF-SHA256** - Master key derivation from root

## Redis State

Cached with TTL (1 hour):

- `vault:keys:master` - Decrypted master key (Fernet encrypted)
- `vault:sealed` - Vault seal status
- `vault:initialized` - Initialization flag

## Environment

Required in `.env`:

```
STORAGE_SERVICE_URL=http://storage:8002
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_pass
JWT_SECRET_KEY=your-secret-key
VAULT_ENCRYPTION_KEY=your-fernet-key
```

Runs on port 8000.
