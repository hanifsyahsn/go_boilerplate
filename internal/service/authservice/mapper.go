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

func ToRegisterResponse(user sqlc.User) (res RegisterResponse) {
	userResponse := userservice.SqlcUserToUserResponse(user)
	res = RegisterResponse{
		UserResponse: userResponse,
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

func ToLoginResponse(user sqlc.User) (res LoginResponse) {
	userResponse := userservice.SqlcUserToUserResponse(user)
	res = LoginResponse{
		UserResponse: userResponse,
	}
	return
}

func ToRefreshTokenResponse(accessToken, refreshToken string) (res TokenResponse) {
	res = ToTokenResponse(accessToken, refreshToken)
	return
}

func ToGetRefreshTokenByUserIdParams(refreshToken string, userId int64) (res sqlc.GetRefreshTokenByUserIdParams) {
	res = sqlc.GetRefreshTokenByUserIdParams{
		UserID:       userId,
		RefreshToken: refreshToken,
	}
	return
}

func ToMeResponse(user sqlc.User) (res MeResponse) {
	userResponse := userservice.SqlcUserToUserResponse(user)
	res = MeResponse{
		UserResponse: userResponse,
	}
	return
}
