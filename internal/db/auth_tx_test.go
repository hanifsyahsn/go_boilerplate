package db

import (
	"context"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/stretchr/testify/require"
)

func TestRegisterTx(t *testing.T) {
	store := NewSQLStore(conf, testDB, tokenMaker)

	createUserParams := sqlc.CreateUserParams{
		Name:     util.RandomString(10),
		Email:    util.RandomString(10),
		Password: util.RandomString(10),
	}

	auth, accessToken, refreshToken, accessClaims, refreshClaims, err := store.RegisterTx(context.Background(), createUserParams)
	require.NoError(t, err)
	require.NotEmpty(t, auth)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	require.Equal(t, createUserParams.Name, auth.Name)
	require.Equal(t, createUserParams.Email, auth.Email)
	require.Equal(t, createUserParams.Email, auth.Email)

	require.NotEmpty(t, auth.ID)
	require.NotEmpty(t, auth.CreatedAt)
	require.NotEmpty(t, auth.UpdatedAt)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	require.Equal(t, accessClaims[constant.EmailKey], auth.Email)
	require.Equal(t, refreshClaims[constant.EmailKey], auth.Email)
}
