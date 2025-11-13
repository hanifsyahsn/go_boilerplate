package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
)

type Maker interface {
	CreateToken(user sqlc.User, accessTokenDuration, RefreshTokenDuration time.Duration) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error)
	VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error)
	RefreshToken(email string, userId int64, accessTokenDuration time.Duration) (accessToken string, err error)
}

func payloadChecker(token *jwt.Token, ok bool, iss string) error {
	v, ok := token.Claims.(jwt.MapClaims)["iss"]
	if !ok {
		return errors.New("invalid token issuer claims")
	}
	if v != iss {
		return errors.New("invalid token issuer")
	}

	_, ok = token.Claims.(jwt.MapClaims)["exp"]
	if !ok {
		return errors.New("invalid token expiration claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)["iat"]
	if !ok {
		return errors.New("invalid token issued at claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)["email"]
	if !ok {
		return errors.New("invalid token email claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)["sub"]
	if !ok {
		return errors.New("invalid token sub claims")
	}
	return nil
}
