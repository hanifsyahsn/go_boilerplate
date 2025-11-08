package authservice

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
	"github.com/lib/pq"

	//"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

type eqCreateUserParamsMatcher struct {
	arg      sqlc.CreateUserParams
	password string
}

func (e eqCreateUserParamsMatcher) Matches(x interface{}) bool {
	arg, ok := x.(sqlc.CreateUserParams)
	if !ok {
		return false
	}
	err := util.CheckPasswordHash(e.password, arg.Password)
	if err != nil {
		return false
	}

	e.arg.Password = arg.Password
	return reflect.DeepEqual(e.arg, arg)
}

func (e eqCreateUserParamsMatcher) String() string {
	return fmt.Sprintf("matches arg %v and password %v", e.arg, e.password)
}

func EqCreateUserParams(arg sqlc.CreateUserParams, password string) gomock.Matcher {
	return eqCreateUserParamsMatcher{arg, password}
}

func TestRegisterService(t *testing.T) {

	testCases := []struct {
		name               string
		svc                func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker) *Service
		registerRequest    RegisterRequest
		toCreateUserParams func(r RegisterRequest) sqlc.CreateUserParams
		user               func(name, email string) sqlc.User
		registerResponse   func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse)
		token              func(email string, tk token.Maker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error)
		buildStub          func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string)
		checkResponse      func(t *testing.T, got, registerResponse RegisterResponse, err error)
	}{
		{
			name: "success",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker) *Service {
				service := NewService(mockStore, nil, nil, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			toCreateUserParams: func(r RegisterRequest) sqlc.CreateUserParams {
				return ToCreateUserParams(r)
			},
			user: func(name, email string) sqlc.User {
				return sqlc.User{
					ID:        util.RandomInt(1, 100),
					Name:      name,
					Email:     email,
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
			token: func(email string, tk token.Maker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				accessToken, refreshToken, refreshTokenExpiration, err = tk.CreateToken(email)
				tokenChecker(t, err, accessToken, refreshToken, refreshTokenExpiration)
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string) {
				store.EXPECT().RegisterTx(gomock.Any(), EqCreateUserParams(param, password)).Times(1).Return(user, accessToken, refreshToken, nil)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				responseChecker(t, got, registerResponse, err)
			},
		},
		{
			name: "failed to hash password",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker) *Service {
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
			toCreateUserParams: func(r RegisterRequest) sqlc.CreateUserParams {
				return ToCreateUserParams(r)
			},
			user: func(name, email string) sqlc.User {
				return sqlc.User{}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk token.Maker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string) {
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "Failed to process password")
			},
		},
		{
			name: "email unique violation",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker) *Service {
				service := NewService(mockStore, hashFunc, checkPassword, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			toCreateUserParams: func(r RegisterRequest) sqlc.CreateUserParams {
				return ToCreateUserParams(r)
			},
			user: func(name, email string) sqlc.User {
				return sqlc.User{}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk token.Maker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string) {
				pqErr := &pq.Error{
					Code:       "23505",
					Constraint: "users_email_unique",
					Message:    "duplicate key value violates unique constraint \"users_email_unique\"",
				}
				store.EXPECT().RegisterTx(gomock.Any(), EqCreateUserParams(param, password)).Times(1).Return(sqlc.User{}, "", "", pqErr)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "Email already exists")
			},
		},
		{
			name: "failed to register user",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker) *Service {
				service := NewService(mockStore, nil, nil, tk)
				require.NotNil(t, service)
				return service
			},
			registerRequest: RegisterRequest{
				Name:     util.RandomString(10),
				Email:    util.RandomString(10),
				Password: util.RandomString(10),
			},
			toCreateUserParams: func(r RegisterRequest) sqlc.CreateUserParams {
				return ToCreateUserParams(r)
			},
			user: func(name, email string) sqlc.User {
				return sqlc.User{
					ID:        util.RandomInt(1, 100),
					Name:      name,
					Email:     email,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
			},
			registerResponse: func(id int64, name, email, accessToken, refreshToken string) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(email string, tk token.Maker) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				return
			},
			buildStub: func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string) {
				store.EXPECT().RegisterTx(gomock.Any(), EqCreateUserParams(param, password)).Times(1).Return(sqlc.User{}, "", "", sql.ErrConnDone)
			},
			checkResponse: func(t *testing.T, got, registerResponse RegisterResponse, err error) {
				require.ErrorContains(t, err, "Failed to register user")
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

			user := testCase.user(registerRequest.Name, registerRequest.Email)

			accessToken, refreshToken, _, err := testCase.token(user.Email, tokenMaker)

			registerResponse := testCase.registerResponse(user.ID, user.Name, user.Email, accessToken, refreshToken)

			arg := testCase.toCreateUserParams(registerRequest)

			testCase.buildStub(mockStore, user, accessToken, refreshToken, arg, registerRequest.Password)

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
