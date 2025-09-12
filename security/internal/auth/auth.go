package auth

import (
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

func InitAuth() {
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	sessionSecret := os.Getenv("SESSION_SECRET")

	if googleClientId == "" || googleClientSecret == "" {
		panic("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set")
	}

	if sessionSecret == "" {
		panic("SESSION_SECRET environment variable must be set")
	}

	// Initialize session store
	store := cookie.NewStore([]byte(sessionSecret))
	store.Options(sessions.Options{
		Path:     "/",
		Domain:   os.Getenv("SESSION_COOKIE_DOMAIN"),
		MaxAge:   86400 * 30, // 30 days
		HttpOnly: true,
		Secure:   os.Getenv("SESSION_COOKIE_SECURE") == "true",
	})
	gothic.Store = store

	// Configure Google provider to request offline access and refresh tokens
	googleProvider := google.New(
		googleClientId,
		googleClientSecret,
		"http://localhost:8080/auth/google/callback",
		"email", "profile", "openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",
	)

	// Set additional parameters for refresh token
	googleProvider.SetPrompt("consent")
	googleProvider.SetAccessType("offline")

	goth.UseProviders(googleProvider)

}
