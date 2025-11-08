package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Maker interface {
	CreateToken(email string) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error)
	VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error)
	RefreshToken(email string) (accessToken string, err error)
}
