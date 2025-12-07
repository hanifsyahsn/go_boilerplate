package token

import (
	"testing"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/factory/userfactory"
	"github.com/stretchr/testify/require"
)

func TestJWTES256(t *testing.T) {
	user := userfactory.NewOptions(nil)
	privateKey, err := LoadECPrivateKey(conf.ECPrivateKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, privateKey)

	publicKey, err := LoadECPublicKey(conf.ECPublicKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, publicKey)

	token := NewTokenMakerES256(privateKey, publicKey, conf.TokenIssuer)

	accessToken, refreshToken, refreshTokenExpiration, err := token.CreateToken(user, conf.AccessTokenDuration, conf.RefreshTokenDuration)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)

	accessJwtToken, accessClaims, err := token.VerifyToken(accessToken)
	require.NoError(t, err)
	require.NotEmpty(t, accessJwtToken)
	require.NotEmpty(t, accessClaims)
	require.Equal(t, accessClaims["email"].(string), user.Email)
	require.Equal(t, accessClaims["iss"].(string), "dev/auth")
	require.WithinDuration(t, time.Now().Add(15*time.Minute),
		time.Unix(int64(accessClaims["exp"].(float64)), 0), time.Second)
	require.WithinDuration(t, time.Now(), time.Unix(int64(accessClaims["iat"].(float64)), 0), time.Second)

	refreshJwtToken, refreshClaims, err := token.VerifyToken(refreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refreshJwtToken)
	require.NotEmpty(t, refreshClaims)
	require.Equal(t, refreshClaims["email"].(string), user.Email)
	require.Equal(t, refreshClaims["iss"].(string), "dev/auth")
	require.Equal(t, int64(refreshClaims["exp"].(float64)), refreshTokenExpiration.Unix())
	require.WithinDuration(t, time.Now(), time.Unix(int64(refreshClaims["iat"].(float64)), 0), time.Second)
}

func TestRefreshTokenES256(t *testing.T) {
	privateKey, err := LoadECPrivateKey(conf.ECPrivateKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, privateKey)

	publicKey, err := LoadECPublicKey(conf.ECPublicKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, publicKey)

	token := NewTokenMakerES256(privateKey, publicKey, conf.TokenIssuer)

	email := "test@mail.com"
	userId := int64(1)

	accessToken, err := token.RefreshToken(email, userId, conf.AccessTokenDuration)

	accessJwtToken, accessClaims, err := token.VerifyToken(accessToken)
	require.NoError(t, err)
	require.NotEmpty(t, accessJwtToken)
	require.NotEmpty(t, accessClaims)
	require.Equal(t, accessClaims["email"].(string), email)
	require.Equal(t, accessClaims["iss"].(string), "dev/auth")
	require.WithinDuration(t, time.Now().Add(15*time.Minute),
		time.Unix(int64(accessClaims["exp"].(float64)), 0), time.Second)
	require.WithinDuration(t, time.Now(), time.Unix(int64(accessClaims["iat"].(float64)), 0), time.Second)
}

func TestExpiredTokenES256(t *testing.T) {
	privateKey, err := LoadECPrivateKey(conf.ECPrivateKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, privateKey)

	publicKey, err := LoadECPublicKey(conf.ECPublicKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, publicKey)

	token := NewTokenMakerES256(privateKey, publicKey, conf.TokenIssuer)

	expiredToken := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAbWFpbC5jb20iLCJleHAiOjE3NjI2NjYyODQsImlhdCI6MTc2MjY2NTM4NCwiaXNzIjoiZGV2L2F1dGgifQ.Z1gbtjpZgG6DMtyR21DxooGO-ZqeoFt96V4jkxfHfkCRZ5-ISUuNeVrbYJryfErTkHgcP5ojuoPJk5wQxbc5-g"

	_, _, err = token.VerifyToken(expiredToken)
	require.Error(t, err)
}
