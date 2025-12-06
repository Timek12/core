# Storage Service

Internal data persistence layer. Stores encrypted data, DEKs, and encryption keys.

## What It Does

- Stores encrypted data in PostgreSQL
- Manages Data Encryption Keys (DEKs)
- Stores Master Key encryption metadata
- Validates JWT tokens for internal requests
- Provides admin endpoints for cross-user queries

## Database

PostgreSQL with tables:

- `data` - Encrypted data values + metadata
- `data_encryption_keys` - Encrypted DEKs (one per data item)
- `encryption_keys` - Master/Root key metadata
- `server_status` - Vault initialization state

## Endpoints

**All endpoints require JWT authentication.**

**Data (Internal):**

- `GET /internal/data` - Get data for authenticated user
- `POST /internal/data` - Create data
- `PUT /internal/data?data_id={id}` - Update data
- `DELETE /internal/data/{id}` - Delete data (with ownership check)

**Admin Data:**

- `GET /internal/data/admin/all` - All data (admin only)
- `GET /internal/data/admin/user/{id}` - User's data (admin only)
- `DELETE /internal/data/admin/{id}` - Delete any data (admin only)

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

```bash
# Database Configuration
DB_HOST=postgres-storage
DB_PORT=5432
DB_NAME=storage
DB_USER=storage_user
DB_PASSWORD=storage_pass

# Server Configuration
HOST=0.0.0.0
PORT=8002

# Debug and Development
DEBUG=false

# Authentication
JWT_SECRET_KEY=your-secret-key-here
```

Runs on port 8002.

## Notes

- This service is **internal only** - not exposed to public
- All requests must include valid JWT token
- Database schema auto-provisions on startup
