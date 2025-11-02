# Server Service

API gateway and business logic layer. Orchestrates communication between UI, Security, and Storage services.

## What It Does

- Vault initialization & unsealing
- Secret encryption/decryption (AES-GCM + DEK)
- Master key management in Redis
- Crypto operations (key derivation, encryption)
- Admin endpoints for managing all secrets

## Dependencies

- **Security Service** - Validates JWT tokens
- **Storage Service** - Persists encrypted data
- **Redis** - Caches master key (with TTL)

## Key Architecture

**Encryption Layers:**

1. Root Key (from external token) → decrypts Master Key
2. Master Key (cached in Redis) → decrypts DEKs
3. DEK (per secret) → encrypts actual secret value

**Vault States:**

- `sealed` - Master key not in memory, secrets inaccessible
- `unsealed` - Master key cached, secrets can be encrypted/decrypted

## Endpoints

**Vault Management:**

- `POST /api/vault/init` - Initialize vault (one-time)
- `POST /api/vault/unseal` - Unseal with external token
- `POST /api/vault/seal` - Clear master key from cache
- `GET /api/vault/status` - Check vault state

**Secrets (User):**

- `GET /api/secrets` - List my secrets
- `POST /api/secrets` - Create new secret
- `PUT /api/secrets/{id}` - Update secret
- `DELETE /api/secrets/{id}` - Delete secret

**Admin:**

- `GET /api/admin/secrets` - View all users' secrets
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
