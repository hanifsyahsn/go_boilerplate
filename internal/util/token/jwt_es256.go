package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MakerES256 struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	env        string
}

func NewTokenMakerES256(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, env string) Maker {
	return &MakerES256{privateKey: privateKey, publicKey: publicKey, env: env}
}

func (maker *MakerES256) CreateToken(email string) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error) {
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

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessToken, err = accessJwt.SignedString(maker.privateKey)
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

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims)
	refreshToken, err = refreshJwt.SignedString(maker.privateKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, refreshTokenExpiration, nil
}

func (maker *MakerES256) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	iss, err := issGenerator(maker.env)
	if err != nil {
		return nil, nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
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

		return maker.publicKey, nil
	})
	if err != nil {
		return nil, nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, jwt.ErrSignatureInvalid
}

func (maker *MakerES256) RefreshToken(email string) (accessToken string, err error) {
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

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessToken, err = accessJwt.SignedString(maker.privateKey)
	if err != nil {
		return "", err
	}

	return
}

func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func LoadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*ecdsa.PublicKey), nil
}

func issGenerator(env string) (string, error) {
	var iss string
	if env == "production" {
		iss = "prod/auth"
	} else if env == "development" {
		iss = "dev/auth"
	} else {
		return "", errors.New("unsupported environment")
	}
	return iss, nil
}
