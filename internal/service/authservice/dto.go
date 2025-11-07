package authservice

import "time"

type RegisterRequest struct {
	Name string `json:"name" binding:"required"`
	// TODO: handle the email error from binding
	Email string `json:"email" binding:"required,email"`
	// TODO: handle the min error from the binding
	Password string `json:"password" binding:"required,min=6"`
}

type RegisterResponse struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}
