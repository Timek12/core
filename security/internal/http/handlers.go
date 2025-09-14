package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LunaGuard/lunaguard-server/internal/auth"
	"github.com/LunaGuard/lunaguard-server/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

// Global instances (will be initialized in main)
var DB *database.DB
var JWTService *auth.JWTService

// ExtractAndValidateToken extracts JWT token from HTTP-only cookie and validates it
func ExtractAndValidateToken(c *gin.Context) (*auth.Claims, error) {
	tokenString, err := c.Cookie("access_token")
	if err != nil {
		return nil, fmt.Errorf("no authentication token provided")
	}

	claims, err := JWTService.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return claims, nil
}

func HandleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "lunaguard-security"})
}

func HandleAuthCallback(c *gin.Context) {
	setProviderForGoth(c)

	user, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Store user in database
	ctx := context.Background()
	dbUser, err := DB.CreateOrUpdateOAuthUser(ctx, user.UserID, user.Email, user.Name, user.AvatarURL, user.Provider)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user"})
		return
	}

	// Store OAuth refresh token in database if provided
	if user.RefreshToken != "" {
		err = DB.StoreRefreshToken(ctx, dbUser.ID, user.RefreshToken, user.ExpiresAt)
		if err != nil {
			fmt.Printf("Failed to store refresh token: %v\n", err)
			// Continue anyway, user is still authenticated
		}
	}

	// Generate JWT tokens for OAuth users (consistent with local auth)
	tokenPair, refreshHash, jti, err := JWTService.GenerateTokenPair(dbUser.ID, dbUser.Email)
	if err != nil {
		fmt.Printf("Failed to generate JWT tokens: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Store JWT refresh token in database
	deviceInfo := json.RawMessage(`{"user_agent": "` + c.GetHeader("User-Agent") + `", "oauth_provider": "` + user.Provider + `"}`)
	clientIP := net.ParseIP(c.ClientIP())
	
	err = DB.StoreJWTRefreshToken(ctx, dbUser.ID, refreshHash, jti, tokenPair.ExpiresAt.Add(7*24*time.Hour), deviceInfo, clientIP)
	if err != nil {
		fmt.Printf("Failed to store JWT refresh token: %v\n", err)
		// Continue anyway
	}

	// Set secure httpOnly cookies with the tokens (for OAuth callback flow)
	maxAge := int(7 * 24 * time.Hour.Seconds()) // 7 days
	secure := false // Set to true in production with HTTPS
	
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", tokenPair.AccessToken, int(time.Until(tokenPair.ExpiresAt).Seconds()), "/", "", secure, true)
	c.SetCookie("refresh_token", tokenPair.RefreshToken, maxAge, "/", "", secure, true)
	
	// Redirect to frontend with success indicator
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3001" // fallback
	}
	frontendURL += "/auth/callback?success=true"
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func HandleCurrentUser(c *gin.Context) {	
	// Extract and validate JWT token using unified approach
	claims, err := ExtractAndValidateToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Get user from database using email from JWT claims
	ctx := context.Background()
	user, err := DB.GetUserByEmail(ctx, claims.Email)
	if err != nil {
		fmt.Printf("Failed to fetch user data for %s: %v\n", claims.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user data"})
		return
	}

	// Return user data
	userData := gin.H{
		"email":      user.Email,
		"provider":   user.AuthMethod,
		"userID":     user.ID,
		"name":       user.Name,
		"avatarURL":  user.AvatarURL,
		"createdAt":  user.CreatedAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user":    userData,
	})
}

func HandleAuthLogout(c *gin.Context) {
	// Clear authentication cookies
	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logout successful",
	})
}

func HandleAuth(c *gin.Context) {
	setProviderForGoth(c)

	// Try to get the user without re-authenticating
	if gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request); err == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"user": gin.H{
				"name":      gothUser.Name,
				"email":     gothUser.Email,
				"provider":  gothUser.Provider,
				"userID":    gothUser.UserID,
				"avatarURL": gothUser.AvatarURL,
				"nickName":  gothUser.NickName,
				"firstName": gothUser.FirstName,
				"lastName":  gothUser.LastName,
			},
		})
	} else {
		// Begin authentication - this will redirect to provider
		gothic.BeginAuthHandler(c.Writer, c.Request)
	}
}

func setProviderForGoth(c *gin.Context) {
	q := c.Request.URL.Query()
	q.Add("provider", c.Param("provider"))
	c.Request.URL.RawQuery = q.Encode()
}

// Local Authentication Handlers

// HandleRegister handles user registration with username/password
func HandleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_failed",
			Message: err.Error(),
		})
		return
	}

	ctx := context.Background()

	// Check if user already exists
	existingUser, _ := DB.GetUserByEmail(ctx, req.Email)
	if existingUser != nil {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "user_exists",
			Message: "A user with this email already exists",
		})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to process registration",
		})
		return
	}

	// Create the user
	user, err := DB.CreateLocalUser(ctx, req.Email, string(hashedPassword))
	if err != nil {
		// Check for unique constraint violations
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			c.JSON(http.StatusConflict, ErrorResponse{
				Error:   "email_taken", 
				Message: "This email is already registered",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to create user",
		})
		return
	}

	// Generate JWT tokens
	tokenPair, refreshHash, jti, err := JWTService.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to generate authentication tokens",
		})
		return
	}

	// Store refresh token in database
	deviceInfo := json.RawMessage(`{"user_agent": "` + c.GetHeader("User-Agent") + `"}`)
	clientIP := net.ParseIP(c.ClientIP())
	
	err = DB.StoreJWTRefreshToken(ctx, user.ID, refreshHash, jti, tokenPair.ExpiresAt.Add(7*24*time.Hour), deviceInfo, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to store authentication session",
		})
		return
	}

	// Set secure httpOnly cookies with tokens
	maxAge := int(7 * 24 * time.Hour.Seconds()) // 7 days
	secure := false // Set to true in production with HTTPS
	
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", tokenPair.AccessToken, int(time.Until(tokenPair.ExpiresAt).Seconds()), "/", "", secure, true)
	c.SetCookie("refresh_token", tokenPair.RefreshToken, maxAge, "/", "", secure, true)

	// Return success response without tokens
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"user": User{
			ID:       user.ID,
			Email:    user.Email,
			Name:     user.Name,
			Provider: user.AuthMethod,
		},
	})
}

// HandleLogin handles user login with email/password
func HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_failed",
			Message: err.Error(),
		})
		return
	}

	ctx := context.Background()

	// Get user by email (local users only for password authentication)
	user, err := DB.GetLocalUserByEmail(ctx, req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	// Generate JWT tokens
	tokenPair, refreshHash, jti, err := JWTService.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to generate authentication tokens",
		})
		return
	}

	// Store refresh token in database
	deviceInfo := json.RawMessage(`{"user_agent": "` + c.GetHeader("User-Agent") + `"}`)
	clientIP := net.ParseIP(c.ClientIP())
	
	err = DB.StoreJWTRefreshToken(ctx, user.ID, refreshHash, jti, tokenPair.ExpiresAt.Add(7*24*time.Hour), deviceInfo, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to store authentication session",
		})
		return
	}

	// Set secure httpOnly cookies with tokens
	maxAge := int(7 * 24 * time.Hour.Seconds()) // 7 days
	secure := false // Set to true in production with HTTPS
	
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", tokenPair.AccessToken, int(time.Until(tokenPair.ExpiresAt).Seconds()), "/", "", secure, true)
	c.SetCookie("refresh_token", tokenPair.RefreshToken, maxAge, "/", "", secure, true)

	// Return success response without tokens
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user": User{
			ID:       user.ID,
			Email:    user.Email,
			Name:     user.Name,
			Provider: user.AuthMethod,
		},
	})
}

// HandleRefreshToken handles JWT refresh token rotation using cookies
func HandleRefreshToken(c *gin.Context) {
	// Get refresh token from cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token",
			Message: "No refresh token found",
		})
		return
	}

	ctx := context.Background()

	// Validate refresh token
	claims, err := JWTService.ValidateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid or expired refresh token",
		})
		return
	}

	// Check if token exists in database and is not revoked
	tokenHash := JWTService.HashRefreshToken(refreshToken)
	dbToken, err := DB.ValidateJWTRefreshToken(ctx, tokenHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token",
			Message: "Refresh token not found or revoked",
		})
		return
	}

	// Get user details
	user, err := DB.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "user_not_found",
			Message: "User account not found",
		})
		return
	}

	// Revoke the old refresh token
	err = DB.RevokeJWTRefreshToken(ctx, tokenHash)
	if err != nil {
		fmt.Printf("Failed to revoke old refresh token: %v\n", err)
		// Continue anyway - user should still get new tokens
	}

	// Generate new token pair
	newTokenPair, newRefreshHash, newJTI, err := JWTService.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to generate new authentication tokens",
		})
		return
	}

	// Store new refresh token in database
	err = DB.StoreJWTRefreshToken(ctx, user.ID, newRefreshHash, newJTI, newTokenPair.ExpiresAt.Add(7*24*time.Hour), dbToken.DeviceInfo, dbToken.IPAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to store new authentication session",
		})
		return
	}

	// Set new cookies
	maxAge := int(7 * 24 * time.Hour.Seconds()) // 7 days
	secure := false // Set to true in production with HTTPS
	
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", newTokenPair.AccessToken, int(time.Until(newTokenPair.ExpiresAt).Seconds()), "/", "", secure, true)
	c.SetCookie("refresh_token", newTokenPair.RefreshToken, maxAge, "/", "", secure, true)

	// Return success response without tokens
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user": User{
			ID:       user.ID,
			Email:    user.Email,
			Name:     user.Name,
			Provider: user.AuthMethod,
		},
	})
}

// HandleLogout handles user logout (revokes refresh tokens and clears cookies)
func HandleLogout(c *gin.Context) {
	ctx := context.Background()
	
	// Try to get refresh token from cookie to revoke it
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil && refreshToken != "" {
		// Revoke the specific refresh token
		tokenHash := JWTService.HashRefreshToken(refreshToken)
		err := DB.RevokeJWTRefreshToken(ctx, tokenHash)
		if err != nil {
			fmt.Printf("Failed to revoke refresh token: %v\n", err)
			// Continue anyway to clear cookies
		}
	}

	// Clear all authentication cookies
	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logged out successfully",
	})
}
