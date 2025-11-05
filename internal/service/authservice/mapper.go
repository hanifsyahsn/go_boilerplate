package authservice

import (
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
)

func ToCreateUserParams(req RegisterRequest) (res sqlc.CreateUserParams) {
	res = sqlc.CreateUserParams{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	return
}

func ToRegisterResponse(user sqlc.User, accessToken string, refreshToken string) (res RegisterResponse) {
	res = RegisterResponse{
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
	return
}

func ToUpsertRefreshTokenParams(userId int64, refreshToken string, refreshTokenExpiration time.Time) (res sqlc.UpsertRefreshTokenParams) {
	res = sqlc.UpsertRefreshTokenParams{
		UserID:       userId,
		RefreshToken: refreshToken,
		ExpiredAt:    refreshTokenExpiration,
	}
	return
}

func ToLoginResponse(user sqlc.User, accessToken string, refreshToken string) (res RegisterResponse) {
	res = RegisterResponse{
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
	return
}
