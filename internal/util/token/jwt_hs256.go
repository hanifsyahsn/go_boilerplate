package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
)

type MakerHS256 struct {
	secretKey string
	issuer    string
}

func NewTokenMakerHS256(secretKey, issuer string) Maker {
	return &MakerHS256{secretKey: secretKey, issuer: issuer}
}

func (maker *MakerHS256) CreateToken(
	user sqlc.User,
	accessTokenDuration,
	RefreshTokenDuration time.Duration,
) (
	accessToken string,
	refreshToken string,
	accessPayload jwt.MapClaims,
	refreshPayload jwt.MapClaims,
	err error,
) {
	accessClaims := jwt.MapClaims{
		constant.SubKey:            user.ID,
		constant.EmailKey:          user.Email,
		constant.IssuerKey:         maker.issuer,
		constant.ExpirationKey:     time.Now().Add(accessTokenDuration).Unix(),
		constant.IssuedAtKey:       time.Now().Unix(),
		constant.JsonWebTokenIdKey: uuid.New().String(),
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", "", jwt.MapClaims{}, jwt.MapClaims{}, err
	}

	refreshClaims := jwt.MapClaims{
		constant.SubKey:            user.ID,
		constant.EmailKey:          user.Email,
		constant.IssuerKey:         maker.issuer,
		constant.ExpirationKey:     time.Now().Add(RefreshTokenDuration).Unix(),
		constant.IssuedAtKey:       time.Now().Unix(),
		constant.JsonWebTokenIdKey: uuid.New().String(),
	}

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", "", jwt.MapClaims{}, jwt.MapClaims{}, err
	}

	return accessToken, refreshToken, accessClaims, refreshClaims, nil
}

func (maker *MakerHS256) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errors.New("unexpected signing method")
		}
		err := payloadChecker(token, ok, maker.issuer)
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

func (maker *MakerHS256) RefreshToken(email string, userId int64, accessTokenDuration time.Duration, jti string) (accessToken string, err error) {
	accessClaims := jwt.MapClaims{
		constant.SubKey:            userId,
		constant.EmailKey:          email,
		constant.IssuerKey:         maker.issuer,
		constant.ExpirationKey:     time.Now().Add(accessTokenDuration).Unix(),
		constant.IssuedAtKey:       time.Now().Unix(),
		constant.JsonWebTokenIdKey: jti,
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", err
	}

	return
}
