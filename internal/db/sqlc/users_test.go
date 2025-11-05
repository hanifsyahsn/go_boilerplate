package sqlc

import (
	"context"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/stretchr/testify/require"
)

func createAUser(t *testing.T) User {
	arg := CreateUserParams{
		Name:     util.RandomString(100),
		Email:    util.RandomString(100),
		Password: util.RandomString(5),
	}
	user, err := testQueries.CreateUser(context.Background(), arg)
	require.NoError(t, err)
	require.NotEmpty(t, user)

	require.Equal(t, arg.Name, user.Name)
	require.Equal(t, arg.Email, user.Email)
	require.Equal(t, arg.Password, user.Password)

	require.NotZero(t, user.ID)
	require.NotZero(t, user.CreatedAt)
	require.NotZero(t, user.UpdatedAt)
	return user
}

func TestCreateUser(t *testing.T) {
	createAUser(t)
}
