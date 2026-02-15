package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestRegisterTx_CreateUserError(t *testing.T) {
	store := NewSQLStore(conf, testDB, tokenMaker)

	email := util.RandomString(10)

	_, err := testDB.Exec(
		`INSERT INTO users (name, email, password) VALUES ($1, $2, $3)`,
		util.RandomString(5),
		email,
		util.RandomString(5),
	)
	require.NoError(t, err)

	arg := sqlc.CreateUserParams{
		Name:     util.RandomString(10),
		Email:    email,
		Password: util.RandomString(10),
	}

	user, accessToken, refreshToken, _, _, err :=
		store.RegisterTx(context.Background(), arg)

	require.Error(t, err)
	require.Empty(t, accessToken)
	require.Empty(t, refreshToken)
	require.Empty(t, user.ID)
}

type failingTokenMaker struct{}

func (f *failingTokenMaker) VerifyToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	return &jwt.Token{}, jwt.MapClaims{}, nil
}

func (f *failingTokenMaker) RefreshToken(email string, userId int64, accessTokenDuration time.Duration, jti string) (accessToken string, err error) {
	return "", nil
}

func (f *failingTokenMaker) CreateToken(
	user sqlc.User,
	accessDuration time.Duration,
	refreshDuration time.Duration,
) (string, string, jwt.MapClaims, jwt.MapClaims, error) {
	return "", "", nil, nil, errors.New("token creation failed")
}

func TestRegisterTx_CreateTokenError(t *testing.T) {
	failingMaker := &failingTokenMaker{}
	store := NewSQLStore(conf, testDB, failingMaker)

	arg := sqlc.CreateUserParams{
		Name:     util.RandomString(10),
		Email:    util.RandomString(10),
		Password: util.RandomString(10),
	}

	_, accessToken, refreshToken, _, _, err :=
		store.RegisterTx(context.Background(), arg)

	require.Error(t, err)
	require.Empty(t, accessToken)
	require.Empty(t, refreshToken)

	user, _ := store.GetUser(context.Background(), arg.Email)
	require.Empty(t, user)
}
