package http

import (
	"net/http"

	"github.com/LunaGuard/lunaguard-server/internal/auth"
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
        claims, err := JWTService.ValidateAccessToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
            c.Abort()
            return
        }

        // Store claims in context for downstream handlers
        c.Set("authClaims", claims)

        c.Next()
    }
}

// GetAuthClaims fetches JWT claims placed by RequireAuth middleware.
func GetAuthClaims(c *gin.Context) (*auth.Claims, bool) {
    v, ok := c.Get("authClaims")
    if !ok {
        return nil, false
    }
    claims, ok := v.(*auth.Claims)
    return claims, ok
}
