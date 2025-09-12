package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAuth middleware that validates JWT tokens from HTTP-only cookies
func RequireAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get access token from HTTP-only cookie
        tokenString, err := c.Cookie("access_token")
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No authentication token provided"})
            c.Abort()
            return
        }

        // Validate access token
        _, err = JWTService.ValidateAccessToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
            c.Abort()
            return
        }

        c.Next()
    }
}
