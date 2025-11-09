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

func (maker *MakerHS256) CreateToken(email string, accessTokenDuration, RefreshTokenDuration time.Duration) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return "", "", time.Time{}, err
	}

	accessClaims := jwt.MapClaims{
		"email": email,
		"iss":   iss,
		"exp":   time.Now().Add(accessTokenDuration).Unix(),
		"iat":   time.Now().Unix(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshTokenExpiration = time.Now().Add(RefreshTokenDuration)

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
		err = maker.payloadChecker(token, ok, iss)
		if err != nil {
			return nil, err
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

func (maker *MakerHS256) payloadChecker(token *jwt.Token, ok bool, iss string) error {
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
	return nil
}

func (maker *MakerHS256) RefreshToken(email string, accessTokenDuration time.Duration) (accessToken string, err error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return "", err
	}

	accessClaims := jwt.MapClaims{
		"email": email,
		"iss":   iss,
		"exp":   time.Now().Add(accessTokenDuration).Unix(),
		"iat":   time.Now().Unix(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", err
	}

	return
}
