package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService struct {
	secretKey    []byte
	issuer       string
	accessTTL    time.Duration
	refreshTTL   time.Duration
}

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	JTI    string `json:"jti"` // JWT ID for refresh tokens
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

func NewJWTService(secretKey []byte, issuer string) *JWTService {
	return &JWTService{
		secretKey:    secretKey,
		issuer:       issuer,
		accessTTL:    15 * time.Minute, // Short-lived access tokens
		refreshTTL:   7 * 24 * time.Hour, // 7 days for refresh tokens
	}
}

// GenerateAccessToken creates a short-lived access token
func (j *JWTService) GenerateAccessToken(userID int, email string) (string, time.Time, error) {
	expiresAt := time.Now().Add(j.accessTTL)
	
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{"client"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// GenerateRefreshToken creates a long-lived refresh token with JTI
func (j *JWTService) GenerateRefreshToken(userID int, email string) (string, string, time.Time, error) {
	jti := uuid.New().String()
	expiresAt := time.Now().Add(j.refreshTTL)
	
	claims := &Claims{
		UserID: userID,
		Email:  email,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{"refresh"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Generate hash for database storage
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	return tokenString, tokenHash, expiresAt, nil
}

// GenerateTokenPair creates both access and refresh tokens
func (j *JWTService) GenerateTokenPair(userID int, email string) (*TokenPair, string, string, error) {
	accessToken, accessExpiry, err := j.GenerateAccessToken(userID, email)
	if err != nil {
		return nil, "", "", err
	}

	refreshToken, refreshHash, _, err := j.GenerateRefreshToken(userID, email)
	if err != nil {
		return nil, "", "", err
	}

	// Get JTI from refresh token for database storage
	claims, err := j.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, "", "", err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiry,
		TokenType:    "Bearer",
	}, refreshHash, claims.JTI, nil
}

// ValidateAccessToken validates and parses an access token
func (j *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Ensure this is an access token (no JTI)
		if claims.JTI != "" {
			return nil, fmt.Errorf("invalid token type: expected access token")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ValidateRefreshToken validates and parses a refresh token
func (j *JWTService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Ensure this is a refresh token (has JTI)
		if claims.JTI == "" {
			return nil, fmt.Errorf("invalid token type: expected refresh token")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// HashRefreshToken creates a SHA256 hash of a refresh token for database storage
func (j *JWTService) HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// GenerateSecureBytes generates cryptographically secure random bytes
func GenerateSecureBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}
