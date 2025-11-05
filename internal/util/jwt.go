package util

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenMaker struct {
	secretKey string
}

func NewTokenMaker(secretKey string) *TokenMaker {
	return &TokenMaker{secretKey: secretKey}
}

func (maker *TokenMaker) CreateToken(email string) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error) {

	accessClaims := jwt.MapClaims{
		"email": email,
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

func (maker *TokenMaker) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

func (maker *TokenMaker) RefreshToken(email string) (accessToken string, err error) {
	accessClaims := jwt.MapClaims{
		"email": email,
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
