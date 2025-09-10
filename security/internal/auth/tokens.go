package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type TokenInfo struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// RefreshGoogleToken refreshes an expired Google access token using the refresh token
func RefreshProviderToken(refreshToken string) (*TokenInfo, error) {
	data := url.Values{}
	data.Set("client_id", os.Getenv("GOOGLE_CLIENT_ID"))
	data.Set("client_secret", os.Getenv("GOOGLE_CLIENT_SECRET"))
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to refresh token, status: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Calculate expiration time
	expiresIn := int64(result["expires_in"].(float64))
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	newRefreshToken := refreshToken // Default to original
	if newRT, exists := result["refresh_token"]; exists && newRT != nil {
		newRefreshToken = newRT.(string)
		fmt.Printf("Google provided new refresh token - updating storage\n")
	} else {
		fmt.Printf("Google did not provide new refresh token - keeping original\n")
	}

	tokenInfo := &TokenInfo{
		AccessToken:  result["access_token"].(string),
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}

	return tokenInfo, nil
}
