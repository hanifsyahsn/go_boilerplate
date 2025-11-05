package authservice

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestRegisterService(t *testing.T) {

	testCases := []struct {
		name             string
		svc              func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk *util.TokenMaker) *Service
		registerRequest  RegisterRequest
		hashedPassword   func(string) string
		user             func(name, email, password string) sqlc.User
		registerResponse func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse)
		token            func(email string, tk *util.TokenMaker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error)
		buildStub        func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string)
		checkResponse    func(t *testing.T, got, registerResponse RegisterResponse, err error)
	}{
		{
			name: "success",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk *util.TokenMaker) *Service {
				service := NewService(mockStore, nil, nil, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			hashedPassword: func(password string) string {
				hashedPass, err := util.HashPassword(password)
				require.NoError(t, err)
				require.NotEmpty(t, hashedPass)

				return hashedPass
			},
			user: func(name, email, password string) sqlc.User {
				return sqlc.User{
					ID:        util.RandomInt(1, 100),
					Name:      name,
					Email:     email,
					Password:  password,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{
					ID:           id,
					Name:         name,
					Email:        email,
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}
				return
			},
			token: func(email string, tk *util.TokenMaker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				accessToken, refreshToken, refreshTokenExpiration, err = tk.CreateToken(email)
				tokenChecker(t, err, accessToken, refreshToken, refreshTokenExpiration)
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string) {
				store.EXPECT().RegisterTx(gomock.Any(), gomock.Any()).Times(1).Return(user, accessToken, refreshToken, nil)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				responseChecker(t, got, registerResponse, err)
			},
		},
		{
			name: "failed to hash password",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk *util.TokenMaker) *Service {
				hashFunc = func(password string) (string, error) {
					return "", fmt.Errorf("failed to hash password")
				}
				service := NewService(mockStore, hashFunc, checkPassword, tk)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			hashedPassword: func(password string) string {
				hashedPass, err := util.HashPassword(password)
				require.NoError(t, err)
				require.NotEmpty(t, hashedPass)

				return hashedPass
			},
			user: func(name, email, password string) sqlc.User {
				return sqlc.User{}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk *util.TokenMaker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string) {
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "failed to process password")
			},
		},
		{
			name: "email unique violation",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk *util.TokenMaker) *Service {
				service := NewService(mockStore, hashFunc, checkPassword, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			hashedPassword: func(password string) string {
				hashedPass, err := util.HashPassword(password)
				require.NoError(t, err)
				require.NotEmpty(t, hashedPass)

				return hashedPass
			},
			user: func(name, email, password string) sqlc.User {
				return sqlc.User{}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk *util.TokenMaker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string) {
				pqErr := &pq.Error{
					Code:       "23505",
					Constraint: "users_email_unique",
					Message:    "duplicate key value violates unique constraint \"users_email_unique\"",
				}
				store.EXPECT().RegisterTx(gomock.Any(), gomock.Any()).Times(1).Return(sqlc.User{}, "", "", pqErr)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "email already exists")
			},
		},
		{
			name: "failed to register user",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk *util.TokenMaker) *Service {
				service := NewService(mockStore, nil, nil, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			hashedPassword: func(password string) string {
				hashedPass, err := util.HashPassword(password)
				require.NoError(t, err)
				require.NotEmpty(t, hashedPass)

				return hashedPass
			},
			user: func(name, email, password string) sqlc.User {
				return sqlc.User{
					ID:        util.RandomInt(1, 100),
					Name:      name,
					Email:     email,
					Password:  password,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk *util.TokenMaker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string) {
				store.EXPECT().RegisterTx(gomock.Any(), gomock.Any()).Times(1).Return(sqlc.User{}, "", "", sql.ErrConnDone)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "failed to register user")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := db.NewMockStore(ctrl)
			svc := testCase.svc(mockStore, util.HashPassword, util.CheckPasswordHash, tokenMaker)

			registerRequest := testCase.registerRequest

			hashedPassword := testCase.hashedPassword(registerRequest.Password)

			user := testCase.user(registerRequest.Name, registerRequest.Email, hashedPassword)

			accessToken, refreshToken, _, err := testCase.token(user.Email, tokenMaker)

			registerResponse := testCase.registerResponse(user.ID, user.Name, user.Email, accessToken, refreshToken)

			testCase.buildStub(mockStore, user, accessToken, refreshToken)

			resUser, resAccessToken, resRefreshToken, err := svc.RegisterService(context.Background(), registerRequest)
			res := ToRegisterResponse(resUser, resAccessToken, resRefreshToken)
			testCase.checkResponse(t, res, registerResponse, err)
		})
	}
}

func tokenChecker(t *testing.T, err error, accessToken string, refreshToken string, refreshTokenExpiration time.Time) {
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)
}

func responseChecker(t *testing.T, res RegisterResponse, registerResponse RegisterResponse, err error) {
	require.NoError(t, err)
	require.NotEmpty(t, res)

	require.Equal(t, registerResponse.ID, res.ID)
	require.Equal(t, registerResponse.AccessToken, res.AccessToken)
	require.Equal(t, registerResponse.RefreshToken, res.RefreshToken)
	require.Equal(t, registerResponse.Name, res.Name)
	require.Equal(t, registerResponse.Email, res.Email)
	require.WithinDuration(t, registerResponse.CreatedAt, res.CreatedAt, time.Second)
	require.WithinDuration(t, registerResponse.UpdatedAt, res.UpdatedAt, time.Second)
}
