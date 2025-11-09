package authservice

import (
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/service/userservice"
)

func ToCreateUserParams(req RegisterRequest) (res sqlc.CreateUserParams) {
	res = sqlc.CreateUserParams{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	return
}

func ToTokenResponse(accessToken string, refreshToken string) (res TokenResponse) {
	res = TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return
}

func ToRegisterResponse(user sqlc.User, accessToken string, refreshToken string) (res RegisterResponse) {
	userResponse := userservice.SqlcUserToUserResponse(user)
	tokenResponse := ToTokenResponse(accessToken, refreshToken)
	res = RegisterResponse{
		UserResponse:  userResponse,
		TokenResponse: tokenResponse,
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

func ToLoginResponse(user sqlc.User, accessToken string, refreshToken string) (res LoginResponse) {
	userResponse := userservice.SqlcUserToUserResponse(user)
	tokenResponse := ToTokenResponse(accessToken, refreshToken)
	res = LoginResponse{
		UserResponse:  userResponse,
		TokenResponse: tokenResponse,
	}
	return
}

func ToRefreshTokenResponse(accessToken, refreshToken string) (res TokenResponse) {
	res = ToTokenResponse(accessToken, refreshToken)
	return
}
