package token

import (
	"testing"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/stretchr/testify/require"
)

func TestJWTHS256(t *testing.T) {
	conf, err := config.LoadConfig("../../..")
	require.NoError(t, err)
	require.NotEmpty(t, conf)

	token := NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)

	email := "test@mail.com"

	//noinspection DuplicatedCode
	accessToken, refreshToken, refreshTokenExpiration, err := token.CreateToken(email)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)

	accessJwtToken, accessClaims, err := token.VerifyToken(accessToken)
	require.NoError(t, err)
	require.NotEmpty(t, accessJwtToken)
	require.NotEmpty(t, accessClaims)
	require.Equal(t, accessClaims["email"].(string), email)
	require.Equal(t, accessClaims["iss"].(string), "dev/auth")
	require.WithinDuration(t, time.Now().Add(15*time.Minute),
		time.Unix(int64(accessClaims["exp"].(float64)), 0), time.Second)
	require.WithinDuration(t, time.Now(), time.Unix(int64(accessClaims["iat"].(float64)), 0), time.Second)

	refreshJwtToken, refreshClaims, err := token.VerifyToken(refreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refreshJwtToken)
	require.NotEmpty(t, refreshClaims)
	require.Equal(t, refreshClaims["email"].(string), email)
	require.Equal(t, refreshClaims["iss"].(string), "dev/auth")
	require.Equal(t, int64(refreshClaims["exp"].(float64)), refreshTokenExpiration.Unix())
	require.WithinDuration(t, time.Now(), time.Unix(int64(refreshClaims["iat"].(float64)), 0), time.Second)
}

func TestRefreshTokenHS256(t *testing.T) {
	conf, err := config.LoadConfig("../../..")
	require.NoError(t, err)
	require.NotEmpty(t, conf)

	token := NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)

	email := "test@mail.com"

	//noinspection DuplicatedCode
	accessToken, err := token.RefreshToken(email)

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
