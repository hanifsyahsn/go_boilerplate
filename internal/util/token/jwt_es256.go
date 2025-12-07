package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
)

type MakerES256 struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
}

func NewTokenMakerES256(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, issuer string) Maker {
	return &MakerES256{privateKey: privateKey, publicKey: publicKey, issuer: issuer}
}

func (maker *MakerES256) CreateToken(user sqlc.User, accessTokenDuration, RefreshTokenDuration time.Duration) (accessToken, refreshToken string, refreshTokenExpiration time.Time, err error) {

	accessClaims := jwt.MapClaims{
		constant.SubKey:        user.ID,
		constant.EmailKey:      user.Email,
		constant.IssuerKey:     maker.issuer,
		constant.ExpirationKey: time.Now().Add(accessTokenDuration).Unix(),
		constant.IssuedAtKey:   time.Now().Unix(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessToken, err = accessJwt.SignedString(maker.privateKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshTokenExpiration = time.Now().Add(RefreshTokenDuration)

	refreshClaims := jwt.MapClaims{
		constant.SubKey:        user.ID,
		constant.EmailKey:      user.Email,
		constant.IssuerKey:     maker.issuer,
		constant.ExpirationKey: refreshTokenExpiration.Unix(),
		constant.IssuedAtKey:   time.Now().Unix(),
	}

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims)
	refreshToken, err = refreshJwt.SignedString(maker.privateKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, refreshTokenExpiration, nil
}

func (maker *MakerES256) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok {
			return nil, errors.New("unexpected signing method")
		}
		err := payloadChecker(token, ok, maker.issuer)
		if err != nil {
			return nil, err
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

func (maker *MakerES256) RefreshToken(email string, userId int64, accessTokenDuration time.Duration) (accessToken string, err error) {

	accessClaims := jwt.MapClaims{
		constant.SubKey:        userId,
		constant.EmailKey:      email,
		constant.IssuerKey:     maker.issuer,
		constant.ExpirationKey: time.Now().Add(accessTokenDuration).Unix(),
		constant.IssuedAtKey:   time.Now().Unix(),
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
