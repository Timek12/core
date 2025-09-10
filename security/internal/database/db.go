package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type DB struct {
	Pool *pgxpool.Pool
}

type User struct {
	ID             int       `json:"id"`
	ProviderUserID string    `json:"provider_user_id,omitempty"`
	Email          string    `json:"email"`
	Name           string    `json:"name"`
	AvatarURL      string    `json:"avatar_url,omitempty"`
	AuthMethod     string    `json:"auth_method"`
	Provider       string    `json:"provider,omitempty"`
	PasswordHash   string    `json:"-"` // Never serialize password hash
	EmailVerified  bool      `json:"email_verified"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type JWTRefreshToken struct {
	ID         int             `json:"id"`
	UserID     int             `json:"user_id"`
	TokenHash  string          `json:"token_hash"`
	JTI        string          `json:"jti"`
	DeviceInfo json.RawMessage `json:"device_info,omitempty"`
	IPAddress  net.IP          `json:"ip_address,omitempty"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Revoked    bool            `json:"revoked"`
	RevokedAt  *time.Time      `json:"revoked_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

type OAuthToken struct {
	ID             int       `json:"id"`
	UserID         int       `json:"user_id"`
	RefreshToken   string    `json:"refresh_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func NewDB() (*DB, error) {
	// Build database URL
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	// Create connection pool with cloud-native retry logic
	pool, err := createConnectionPoolWithRetry(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	// Verify that required tables exist (with retries for eventual consistency)
	if err := waitForDatabaseSchema(pool); err != nil {
		return nil, fmt.Errorf("database schema verification failed: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// createConnectionPoolWithRetry creates database connection pool with retry logic
func createConnectionPoolWithRetry(dbURL string) (*pgxpool.Pool, error) {
	maxRetries := 10
	retryDelay := time.Second * 2
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		pool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			if attempt < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay *= 2 // Exponential backoff
				continue
			}
			return nil, err
		}

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := pool.Ping(ctx); err != nil {
			cancel()
			pool.Close()
			if attempt < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay *= 2
				continue
			}
			return nil, err
		}
		cancel()

		return pool, nil
	}
	
	return nil, fmt.Errorf("failed to connect to database after %d attempts", maxRetries)
}

// waitForDatabaseSchema waits for database schema to be available (cloud-native)
func waitForDatabaseSchema(pool *pgxpool.Pool) error {
	maxRetries := 30 // Wait up to 60 seconds (30 * 2s)
	retryDelay := time.Second * 2
	
	requiredTables := []string{"users", "oauth_tokens", "jwt_refresh_tokens"}
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		allTablesExist := true
		
		for _, table := range requiredTables {
			var exists bool
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			query := `
				SELECT EXISTS (
					SELECT FROM information_schema.tables 
					WHERE table_name = $1 AND table_schema = 'public'
				)`
			
			err := pool.QueryRow(ctx, query, table).Scan(&exists)
			cancel()
			
			if err != nil || !exists {
				allTablesExist = false
				break
			}
		}
		
		if allTablesExist {
			return nil
		}
		
		if attempt < maxRetries-1 {
			time.Sleep(retryDelay)
		}
	}
	
	return fmt.Errorf("required database tables not available after waiting %d seconds. Ensure storage service has provisioned the schema", maxRetries*2)
}

func (db *DB) Close() {
	db.Pool.Close()
}

// CreateOrUpdateOAuthUser creates a new OAuth user or updates existing one
func (db *DB) CreateOrUpdateOAuthUser(ctx context.Context, providerUserID, email, name, avatarURL, provider string) (*User, error) {
	var user User
	query := `
		INSERT INTO users (provider_user_id, email, name, avatar_url, auth_method, provider, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $5, NOW())
		ON CONFLICT (provider_user_id, provider) 
		DO UPDATE SET 
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			avatar_url = EXCLUDED.avatar_url,
			updated_at = NOW()
		RETURNING user_id, provider_user_id, email, name, avatar_url, auth_method, provider, email_verified, created_at, updated_at`

	err := db.Pool.QueryRow(ctx, query, providerUserID, email, name, avatarURL, provider).Scan(
		&user.ID,
		&user.ProviderUserID,
		&user.Email,
		&user.Name,
		&user.AvatarURL,
		&user.AuthMethod,
		&user.Provider,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create or update OAuth user: %w", err)
	}

	return &user, nil
}

// CreateLocalUser creates a new user with email/password authentication
func (db *DB) CreateLocalUser(ctx context.Context, email, passwordHash string) (*User, error) {
	var user User
	query := `
		INSERT INTO users (email, password_hash, auth_method, name, updated_at) 
		VALUES ($1, $2, 'local', $1, NOW())
		RETURNING user_id, email, name, auth_method, email_verified, created_at, updated_at`

	err := db.Pool.QueryRow(ctx, query, email, passwordHash).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.AuthMethod,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create local user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail finds a user by email regardless of auth method
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	var providerUserID, avatarURL, provider, passwordHash sql.NullString
	
	query := `
		SELECT user_id, provider_user_id, email, name, avatar_url, auth_method, provider, password_hash, email_verified, created_at, updated_at 
		FROM users 
		WHERE email = $1`

	err := db.Pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&providerUserID,
		&user.Email,
		&user.Name,
		&avatarURL,
		&user.AuthMethod,
		&provider,
		&passwordHash,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	// Handle nullable fields
	if providerUserID.Valid {
		user.ProviderUserID = providerUserID.String
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetLocalUserByEmail finds a local user by email (for password authentication)
func (db *DB) GetLocalUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	query := `
		SELECT user_id, email, name, password_hash, auth_method, email_verified, created_at, updated_at 
		FROM users 
		WHERE email = $1 AND auth_method = 'local'`

	err := db.Pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.PasswordHash,
		&user.AuthMethod,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByID finds a user by their internal ID
func (db *DB) GetUserByID(ctx context.Context, userID int) (*User, error) {
	var user User
	var providerUserID, avatarURL, provider sql.NullString
	
	query := `
		SELECT user_id, provider_user_id, email, name, avatar_url, auth_method, provider, email_verified, created_at, updated_at 
		FROM users 
		WHERE user_id = $1`

	err := db.Pool.QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&providerUserID,
		&user.Email,
		&user.Name,
		&avatarURL,
		&user.AuthMethod,
		&provider,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	// Handle nullable fields
	if providerUserID.Valid {
		user.ProviderUserID = providerUserID.String
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}


// StoreRefreshToken stores or updates refresh token for user
func (db *DB) StoreRefreshToken(ctx context.Context, userID int, refreshToken string, expiresAt time.Time) error {
	query := `
		INSERT INTO oauth_tokens (user_id, provider, refresh_token, token_expires_at)
		VALUES ($1, 'google', $2, $3)
		ON CONFLICT (user_id, provider) DO UPDATE SET
			refresh_token = EXCLUDED.refresh_token,
			token_expires_at = EXCLUDED.token_expires_at,
			updated_at = NOW()`

	_, err := db.Pool.Exec(ctx, query, userID, refreshToken, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves refresh token for user
func (db *DB) GetRefreshToken(ctx context.Context, userID int) (string, error) {
	var refreshToken string

	query := `SELECT refresh_token FROM oauth_tokens WHERE user_id = $1`

	err := db.Pool.QueryRow(ctx, query, userID).Scan(&refreshToken)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no refresh token found for user")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	return refreshToken, nil
}

// DeleteRefreshToken removes refresh token (on logout)
func (db *DB) DeleteRefreshToken(ctx context.Context, userID int) error {
	query := `DELETE FROM oauth_tokens WHERE user_id = $1`

	_, err := db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

// JWT Refresh Token Methods

// StoreJWTRefreshToken stores a JWT refresh token in the database
func (db *DB) StoreJWTRefreshToken(ctx context.Context, userID int, tokenHash, jti string, expiresAt time.Time, deviceInfo json.RawMessage, ipAddress net.IP) error {
	query := `
		INSERT INTO jwt_refresh_tokens (user_id, token_hash, jti, device_info, ip_address, expires_at) 
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := db.Pool.Exec(ctx, query, userID, tokenHash, jti, deviceInfo, ipAddress, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store JWT refresh token: %w", err)
	}

	return nil
}

// ValidateJWTRefreshToken checks if a JWT refresh token is valid and not revoked
func (db *DB) ValidateJWTRefreshToken(ctx context.Context, tokenHash string) (*JWTRefreshToken, error) {
	var token JWTRefreshToken
	query := `
		SELECT id, user_id, token_hash, jti, device_info, ip_address, expires_at, revoked, revoked_at, created_at
		FROM jwt_refresh_tokens 
		WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`

	err := db.Pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.JTI,
		&token.DeviceInfo,
		&token.IPAddress,
		&token.ExpiresAt,
		&token.Revoked,
		&token.RevokedAt,
		&token.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWT refresh token: %w", err)
	}

	return &token, nil
}

// RevokeJWTRefreshToken marks a JWT refresh token as revoked
func (db *DB) RevokeJWTRefreshToken(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE jwt_refresh_tokens 
		SET revoked = TRUE, revoked_at = NOW() 
		WHERE token_hash = $1`

	result, err := db.Pool.Exec(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to revoke JWT refresh token: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("JWT refresh token not found")
	}

	return nil
}

// RevokeAllJWTRefreshTokens revokes all JWT refresh tokens for a user (logout from all devices)
func (db *DB) RevokeAllJWTRefreshTokens(ctx context.Context, userID int) error {
	query := `
		UPDATE jwt_refresh_tokens 
		SET revoked = TRUE, revoked_at = NOW() 
		WHERE user_id = $1 AND revoked = FALSE`

	_, err := db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all JWT refresh tokens: %w", err)
	}

	return nil
}

// CleanupExpiredJWTRefreshTokens removes expired JWT refresh tokens (should be run periodically)
func (db *DB) CleanupExpiredJWTRefreshTokens(ctx context.Context) error {
	query := `DELETE FROM jwt_refresh_tokens WHERE expires_at <= NOW()`

	result, err := db.Pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired JWT refresh tokens: %w", err)
	}

	fmt.Printf("Cleaned up %d expired JWT refresh tokens\n", result.RowsAffected())
	return nil
}

// GetActiveJWTRefreshTokensForUser returns all active refresh tokens for a user
func (db *DB) GetActiveJWTRefreshTokensForUser(ctx context.Context, userID int) ([]JWTRefreshToken, error) {
	var tokens []JWTRefreshToken
	query := `
		SELECT id, user_id, token_hash, jti, device_info, ip_address, expires_at, revoked, revoked_at, created_at
		FROM jwt_refresh_tokens 
		WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC`

	rows, err := db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active JWT refresh tokens: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var token JWTRefreshToken
		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&token.JTI,
			&token.DeviceInfo,
			&token.IPAddress,
			&token.ExpiresAt,
			&token.Revoked,
			&token.RevokedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan JWT refresh token: %w", err)
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}
