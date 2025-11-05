package sqlc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateRefreshToken(t *testing.T) {
	user := createAUser(t)
	arg := CreateRefreshTokenParams{
		UserID:       user.ID,
		RefreshToken: "refresh_token",
		ExpiredAt:    time.Now(),
	}

	accessToken, err := testQueries.CreateRefreshToken(context.Background(), arg)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)

	require.Equal(t, arg.UserID, accessToken.UserID)
	require.Equal(t, arg.RefreshToken, accessToken.RefreshToken)
	require.WithinDuration(t, arg.ExpiredAt, accessToken.ExpiredAt, time.Second)

	require.NotZero(t, accessToken.ID)
	require.NotZero(t, accessToken.CreatedAt)
	require.NotZero(t, accessToken.UpdatedAt)
}
