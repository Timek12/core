# Security Service

Handles user authentication and JWT token management.

## What It Does

- User login/logout
- JWT token creation & validation
- Password hashing with Argon2
- Refresh token rotation
- User management (admin only)

## Database

PostgreSQL with tables:

- `users` - User accounts
- `jwt_refresh_tokens` - Active sessions

## Endpoints

**Public:**

- `POST /auth/login` - Login with email/password
- `POST /auth/refresh` - Get new access token

**Authenticated:**

- `GET /auth/me` - Get current user info
- `POST /auth/logout` - Logout current session
- `GET /auth/sessions` - List active sessions

**Admin Only:**

- `GET /auth/admin/users` - List all users
- `PUT /auth/admin/users/{id}` - Update user role
- `DELETE /auth/admin/users/{id}` - Delete user

## JWT Tokens

**Access Token:**

- Lifetime: 30 minutes
- Contains: user_id, email, roles
- Algorithm: HS256

**Refresh Token:**

- Lifetime: 7 days
- Stored as SHA-256 hash
- Single-use rotation

## Environment

Required variables in `.env`:

```bash
# Database Configuration
DB_HOST=postgres-security
DB_PORT=5432
DB_NAME=security
DB_USER=security_user
DB_PASSWORD=security_pass

# Server Configuration
HOST=0.0.0.0
PORT=8001

# Debug and Development
DEBUG=false

# Authentication
JWT_SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

Runs on port 8001.
