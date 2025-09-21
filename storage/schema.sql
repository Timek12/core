-- LunaGuard Storage Service Database Schema
-- Comprehensive schema for all LunaGuard services

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for authentication (used by security service)
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    provider_user_id VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    avatar_url TEXT,
    auth_method VARCHAR(50) NOT NULL DEFAULT 'oauth',
    provider VARCHAR(50) NOT NULL DEFAULT 'github',
    password_hash VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_user_id, provider)
);

-- OAuth refresh tokens table (for storing external OAuth tokens)
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    refresh_token TEXT NOT NULL,
    token_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    UNIQUE(user_id, provider)
);

-- JWT refresh tokens table (for internal JWT token management)
CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL, -- Hashed refresh token
    jti UUID NOT NULL DEFAULT uuid_generate_v4(), -- JWT ID for token identification
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    device_info JSONB, -- User agent, IP, etc.
    ip_address INET,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    UNIQUE(token_hash),
    UNIQUE(jti)
);

-- Secrets table (used by server service)
CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(256) NOT NULL,
    description TEXT NOT NULL,
    key_id UUID NOT NULL,
    encrypted_value TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_user_id ON users(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_provider ON oauth_refresh_tokens(user_id, provider);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_user_id ON jwt_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_jti ON jwt_refresh_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_hash ON jwt_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_expires ON jwt_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_jwt_tokens_active ON jwt_refresh_tokens(user_id, revoked, expires_at);
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_key_id ON secrets(key_id);

-- Update trigger for users table
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Drop and recreate triggers to avoid "already exists" errors
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_secrets_updated_at ON secrets;
CREATE TRIGGER update_secrets_updated_at BEFORE UPDATE ON secrets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Clean up expired tokens function
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    -- Clean up expired OAuth refresh tokens
    DELETE FROM oauth_refresh_tokens 
    WHERE token_expires_at IS NOT NULL AND token_expires_at < NOW();
    
    -- Clean up expired JWT refresh tokens
    DELETE FROM jwt_refresh_tokens 
    WHERE expires_at < NOW();
    
    -- Mark revoked tokens older than 30 days for cleanup
    UPDATE jwt_refresh_tokens 
    SET revoked = true 
    WHERE created_at < NOW() - INTERVAL '30 days' AND NOT revoked;
END;
$$ LANGUAGE plpgsql;
