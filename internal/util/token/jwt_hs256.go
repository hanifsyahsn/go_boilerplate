package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MakerHS256 struct {
	secretKey string
	env       string
}

func NewTokenMakerHS256(secretKey, env string) Maker {
	return &MakerHS256{secretKey: secretKey, env: env}
}

func (maker *MakerHS256) CreateToken(email string) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return "", "", time.Time{}, err
	}

	accessClaims := jwt.MapClaims{
		"email": email,
		"iss":   iss,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshTokenExpiration = time.Now().Add(7 * 24 * time.Hour)

	refreshClaims := jwt.MapClaims{
		"email": email,
		"iss":   iss,
		"exp":   refreshTokenExpiration.Unix(),
		"iat":   time.Now().Unix(),
	}

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, refreshTokenExpiration, nil
}

func (maker *MakerHS256) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return nil, nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errors.New("unexpected signing method")
		}
		v, ok := token.Claims.(jwt.MapClaims)["iss"]
		if !ok {
			return nil, errors.New("invalid token issuer claims")
		}
		if v != iss {
			return nil, errors.New("invalid token issuer")
		}

		return []byte(maker.secretKey), nil
	})
	if err != nil {
		return nil, nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, jwt.ErrSignatureInvalid
}

func (maker *MakerHS256) RefreshToken(email string) (accessToken string, err error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return "", err
	}

	accessClaims := jwt.MapClaims{
		"email": email,
		"iss":   iss,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", err
	}

	return
}
