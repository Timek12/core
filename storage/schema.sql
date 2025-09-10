-- LunaGuard Database Schema
-- Version: 1.0
-- Description: Complete database schema for LunaGuard platform

-- Users table: Core user information for both OAuth and local users
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    provider_user_id VARCHAR(128),
    email VARCHAR(256) UNIQUE NOT NULL,
    name VARCHAR(256),
    avatar_url TEXT,
    auth_method VARCHAR(32) NOT NULL DEFAULT 'local',
    provider VARCHAR(32),
    password_hash TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(provider_user_id, provider)
);

-- OAuth tokens table: External provider refresh tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    refresh_token TEXT NOT NULL,
    token_expires_at TIMESTAMP,
    scope TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, provider)
);

-- JWT refresh tokens table: Internal token management
CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    jti VARCHAR(36) NOT NULL UNIQUE,
    device_info JSONB,
    ip_address INET,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider_user_id, provider);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_provider ON oauth_tokens(user_id, provider);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_user_id ON jwt_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_hash ON jwt_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_jti ON jwt_refresh_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_active ON jwt_refresh_tokens(user_id, revoked, expires_at);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_expires ON jwt_refresh_tokens(expires_at) WHERE revoked = FALSE;
