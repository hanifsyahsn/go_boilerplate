package authservice

import (
	"github.com/hanifsyahsn/go_boilerplate/internal/service/userservice"
)

type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RegisterResponse struct {
	UserResponse  userservice.UserResponse `json:"user"`
	TokenResponse TokenResponse            `json:"token"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	UserResponse  userservice.UserResponse `json:"user"`
	TokenResponse TokenResponse            `json:"token"`
}

type MeResponse struct {
	UserResponse userservice.UserResponse `json:"user"`
}

type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
}
