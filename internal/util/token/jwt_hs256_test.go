package token

import (
	"testing"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/factory/userfactory"
	"github.com/stretchr/testify/require"
)

func TestJWTHS256(t *testing.T) {
	token := NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)

	user := userfactory.NewOptions(nil)

	//noinspection DuplicatedCode
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

func TestRefreshTokenHS256(t *testing.T) {
	token := NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)

	email := "test@mail.com"
	userId := int64(1)

	//noinspection DuplicatedCode
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

func TestExpiredTokenHS256(t *testing.T) {
	token := NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)

	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAbWFpbC5jb20iLCJleHAiOjE3NjI2NjY4MzcsImlhdCI6MTc2MjY2NTkzNywiaXNzIjoiZGV2L2F1dGgifQ.jJXJkYWEGpxukhPLWOFv4Fzptvtop-3eJIKZBvNjp_k"

	_, _, err := token.VerifyToken(expiredToken)
	require.Error(t, err)
}
