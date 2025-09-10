package http

type EncryptRequest struct {
	Data      string `json:"data" binding:"required"`
	KeyPhrase string `json:"keyPhrase" binding:"required"`
}

type EncryptResponse struct {
	Data string `json:"data"`
}

type DecryptRequest struct {
	Data      string `json:"data" binding:"required"`
	KeyPhrase string `json:"keyPhrase" binding:"required"`
}

type DecryptResponse struct {
	Data string `json:"data"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	Name     string `json:"name" binding:"required,min=1,max=100"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Success bool `json:"success"`
	User    User `json:"user"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
