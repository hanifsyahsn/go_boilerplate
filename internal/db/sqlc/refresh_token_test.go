package sqlc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func generateRefreshToken(t *testing.T) RefreshToken {
	user := createAUser(t)
	arg := CreateRefreshTokenParams{
		UserID:       user.ID,
		RefreshToken: "refresh_token",
		ExpiredAt:    time.Now(),
	}

	refreshToken, err := testQueries.CreateRefreshToken(context.Background(), arg)
	require.NoError(t, err)
	require.NotEmpty(t, refreshToken)

	require.Equal(t, arg.UserID, refreshToken.UserID)
	require.Equal(t, arg.RefreshToken, refreshToken.RefreshToken)
	require.WithinDuration(t, arg.ExpiredAt, refreshToken.ExpiredAt, time.Second)

	require.NotZero(t, refreshToken.ID)
	require.NotZero(t, refreshToken.CreatedAt)
	require.NotZero(t, refreshToken.UpdatedAt)
	return refreshToken
}

func TestCreateRefreshToken(t *testing.T) {
	_ = generateRefreshToken(t)
}

func TestDeleteRefreshToken(t *testing.T) {
	refreshToken := generateRefreshToken(t)

	err := testQueries.DeleteRefreshToken(context.Background(), refreshToken.RefreshToken)
	require.NoError(t, err)
}

func TestGetRefreshTokenByUserId(t *testing.T) {
	refreshToken := generateRefreshToken(t)
	arg := GetRefreshTokenByUserIdParams{
		RefreshToken: refreshToken.RefreshToken,
		UserID:       refreshToken.UserID,
	}
	refreshTokenUser, err := testQueries.GetRefreshTokenByUserId(context.Background(), arg)
	require.NoError(t, err)
	require.Equal(t, refreshToken.UserID, refreshTokenUser.UserID)
}

func TestUpsertRefreshToken(t *testing.T) {
	refreshToken := generateRefreshToken(t)
	arg := UpsertRefreshTokenParams{
		RefreshToken: "refresh_token",
		UserID:       refreshToken.UserID,
		ExpiredAt:    time.Now(),
	}
	upsertedRefreshToken, err := testQueries.UpsertRefreshToken(context.Background(), arg)
	require.NoError(t, err)
	require.Equal(t, arg.RefreshToken, upsertedRefreshToken.RefreshToken)
}
