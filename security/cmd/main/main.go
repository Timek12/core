package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/LunaGuard/lunaguard-server/internal/auth"
	"github.com/LunaGuard/lunaguard-server/internal/database"
	"github.com/LunaGuard/lunaguard-server/internal/http"
)

func main() {
	// Load environment variables from .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("Error loading .env file:", err)
		log.Println("Continuing with environment variables from docker-compose...")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Initialize database
	db, err := database.NewDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Initialize services
	jwtService := auth.NewJWTService([]byte(jwtSecret), "lunaguard-server")

	// Set global instances for handlers
	http.DB = db
	http.JWTService = jwtService

	// Initialize OAuth providers
	auth.InitAuth()

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true, // Required for cookies
		MaxAge:           12 * time.Hour,
	}))

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Health check
	router.GET("/health", http.HandleHealth)

		// OAuth routes
	router.GET("/auth/:provider", http.HandleAuth)
	router.GET("/auth/:provider/callback", http.HandleAuthCallback)
	router.POST("/logout", http.HandleAuthLogout)
	router.GET("/user", http.HandleCurrentUser)

	// Local authentication routes
	router.POST("/register", http.HandleRegister)
	router.POST("/login", http.HandleLogin)
	router.POST("/refresh", http.HandleRefreshToken)
	
	// Get port from environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	router.Run("127.0.0.1:" + port)
}
