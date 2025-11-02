# Storage Service

Internal data persistence layer. Stores encrypted secrets, DEKs, and encryption keys.

## What It Does

- Stores encrypted secrets in PostgreSQL
- Manages Data Encryption Keys (DEKs)
- Stores Master Key encryption metadata
- Validates JWT tokens for internal requests
- Provides admin endpoints for cross-user queries

## Database

PostgreSQL with tables:

- `secrets` - Encrypted secret values + metadata
- `data_encryption_keys` - Encrypted DEKs (one per secret)
- `encryption_keys` - Master/Root key metadata
- `server_status` - Vault initialization state

## Endpoints

**All endpoints require JWT authentication.**

**Secrets (Internal):**

- `GET /internal/secrets` - Get secrets for authenticated user
- `POST /internal/secrets` - Create secret
- `PUT /internal/secrets?secret_id={id}` - Update secret
- `DELETE /internal/secrets/{id}` - Delete secret (with ownership check)

**Admin Secrets:**

- `GET /internal/secrets/admin/all` - All secrets (admin only)
- `GET /internal/secrets/admin/user/{id}` - User's secrets (admin only)
- `DELETE /internal/secrets/admin/{id}` - Delete any secret (admin only)

**DEK Management:**

- `POST /internal/deks` - Store new DEK
- `GET /internal/deks/{id}` - Retrieve DEK

**Keys:**

- `GET /internal/keys` - List encryption keys
- `POST /internal/keys` - Store key metadata
- `GET /internal/keys/type/{type}` - Get key by type

**Status:**

- `GET /internal/status` - Server/vault status
- `PUT /internal/status` - Update status (admin only)

## Security

**User Isolation:**

- Each request validates JWT token
- Endpoints filter by `user_id` from token
- Ownership checks on update/delete

## Data Model

**Secret:**

```python
{
  "id": "uuid",
  "user_id": 1,
  "name": "AWS_KEY",
  "encrypted_value": "hex",
  "nonce": "hex",
  "dek_id": "uuid",
  "version": 1,
  "is_active": true,
  "created_at": "timestamp"
}
```

**DEK (Data Encryption Key):**

```python
{
  "id": "uuid",
  "encrypted_dek": "hex",  # Encrypted by master key
  "nonce": "hex",
  "created_at": "timestamp"
}
```

## Environment

Required in `.env`:

```
DB_HOST=postgres-storage
DB_PORT=5432
DB_NAME=storage
DB_USER=storage_user
DB_PASSWORD=storage_pass

JWT_SECRET_KEY=your-secret-key
INTERNAL_SERVICE_TOKEN=service-token
```

Runs on port 8002.

## Notes

- This service is **internal only** - not exposed to public
- All requests must include valid JWT token
- Database schema auto-provisions on startup
