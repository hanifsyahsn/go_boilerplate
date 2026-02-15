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

func TestGetUser(t *testing.T) {
	user := createAUser(t)
	getUserByEmail, err := testQueries.GetUser(context.Background(), user.Email)
	require.NoError(t, err)
	require.Equal(t, user.Name, getUserByEmail.Name)
	require.Equal(t, user.Email, getUserByEmail.Email)
	require.Equal(t, user.ID, getUserByEmail.ID)
}
