-- LunaGuard Database Schema

-- Users table: Supports both OAuth and local authentication
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,        -- Internal user ID (auto-increment)
    provider_user_id VARCHAR(128),     -- External provider ID (Google ID, GitHub ID, etc.)
    email VARCHAR(256) UNIQUE NOT NULL,
    name VARCHAR(256),
    avatar_url TEXT,
    
    -- Authentication method and provider info
    auth_method VARCHAR(32) NOT NULL DEFAULT 'local', -- 'local', 'google' etc.
    provider VARCHAR(32),              -- 'google', 'apple', etc. (NULL for local users)
    
    -- Local authentication fields
    password_hash TEXT,                -- bcrypt hash for local users
    email_verified BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_auth_method CHECK (auth_method IN ('local', 'google', 'apple')),
    CONSTRAINT oauth_fields_required CHECK (
        (auth_method = 'local' AND password_hash IS NOT NULL) OR
        (auth_method != 'local' AND provider_user_id IS NOT NULL AND provider IS NOT NULL)
    ),
    CONSTRAINT unique_provider_user CHECK (
        (auth_method = 'local') OR 
        (auth_method != 'local' AND provider_user_id IS NOT NULL)
    ),
    UNIQUE(provider_user_id, provider) -- OAuth users: unique per provider
);

-- OAuth tokens table: For external provider refresh tokens only
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL DEFAULT 'google', -- 'google', 'apple', etc.
    refresh_token TEXT NOT NULL,   -- Only store long-lived refresh tokens
    token_expires_at TIMESTAMP,    -- When the refresh token expires
    scope TEXT, -- Requested scopes
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- One token per user per provider
    UNIQUE(user_id, provider)
);

-- JWT refresh tokens table: For internal JWT-based auth
CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL, -- SHA256 hash of the refresh token
    jti VARCHAR(36) NOT NULL UNIQUE, -- JWT ID (UUID)
    device_info JSONB, -- Browser, OS, etc.
    ip_address INET,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Index for fast lookups
    UNIQUE(token_hash)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_provider_users_id ON users(provider_user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_tokens_updated_at BEFORE UPDATE ON oauth_tokens 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
