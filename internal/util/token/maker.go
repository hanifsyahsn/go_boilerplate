package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
)

type Maker interface {
	CreateToken(
		user sqlc.User,
		accessTokenDuration,
		RefreshTokenDuration time.Duration,
	) (
		accessToken string,
		refreshToken string,
		accessPayload jwt.MapClaims,
		refreshPayload jwt.MapClaims,
		err error,
	)
	VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error)
	RefreshToken(email string, userId int64, accessTokenDuration time.Duration, jti string) (accessToken string, err error)
}

func payloadChecker(token *jwt.Token, ok bool, iss string) error {
	v, ok := token.Claims.(jwt.MapClaims)[constant.IssuerKey]
	if !ok {
		return errors.New("invalid token issuer claims")
	}
	if v != iss {
		return errors.New("invalid token issuer")
	}

	_, ok = token.Claims.(jwt.MapClaims)[constant.ExpirationKey]
	if !ok {
		return errors.New("invalid token expiration claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)[constant.IssuedAtKey]
	if !ok {
		return errors.New("invalid token issued at claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)[constant.EmailKey]
	if !ok {
		return errors.New("invalid token email claims")
	}

	_, ok = token.Claims.(jwt.MapClaims)[constant.SubKey]
	if !ok {
		return errors.New("invalid token sub claims")
	}
	return nil
}
