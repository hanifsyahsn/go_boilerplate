package authservice

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/factory/userfactory"
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
		svc                func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker, conf config.Config) *Service
		registerRequest    RegisterRequest
		toCreateUserParams func(r RegisterRequest) sqlc.CreateUserParams
		user               sqlc.User
		registerResponse   func(user sqlc.User) (registerResponse RegisterResponse)
		token              func(tk token.Maker, conf config.Config, user sqlc.User) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error)
		buildStub          func(store *db.MockStore, user sqlc.User, accessToken, refreshToken string, param sqlc.CreateUserParams, password string)
		checkResponse      func(t *testing.T, got, registerResponse RegisterResponse, err error)
	}{
		{
			name: "success",
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker, conf config.Config) *Service {
				service := NewService(mockStore, hashFunc, checkPassword, tk, conf)
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
			user: userfactory.NewOptions(nil),
			registerResponse: func(user sqlc.User) (registerResponse RegisterResponse) {
				registerResponse = ToRegisterResponse(user)
				return
			},
			token: func(tk token.Maker, conf config.Config, user sqlc.User) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
				accessToken, refreshToken, refreshTokenExpiration, err = tk.CreateToken(user, conf.AccessTokenDuration, conf.RefreshTokenDuration)
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
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker, conf config.Config) *Service {
				hashFunc = func(password string) (string, error) {
					return "", fmt.Errorf("failed to hash password")
				}
				service := NewService(mockStore, hashFunc, checkPassword, tk, conf)
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
			user: sqlc.User{},
			registerResponse: func(user sqlc.User) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(tk token.Maker, conf config.Config, user sqlc.User) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
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
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker, conf config.Config) *Service {
				service := NewService(mockStore, hashFunc, checkPassword, tk, conf)
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
			user: sqlc.User{},
			registerResponse: func(user sqlc.User) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(tk token.Maker, conf config.Config, user sqlc.User) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
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
			svc: func(mockStore *db.MockStore, hashFunc func(string) (string, error), checkPassword func(password, hash string) error, tk token.Maker, conf config.Config) *Service {
				service := NewService(mockStore, hashFunc, checkPassword, tk, conf)
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
			user: userfactory.NewOptions(nil),
			registerResponse: func(user sqlc.User) (registerResponse RegisterResponse) {
				registerResponse = RegisterResponse{}
				return
			},
			token: func(tk token.Maker, conf config.Config, user sqlc.User) (accessToken string, refreshToken string, refreshTokenExpiration time.Time, err error) {
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
			svc := testCase.svc(mockStore, util.HashPassword, util.CheckPasswordHash, tokenMaker, conf)

			registerRequest := testCase.registerRequest

			user := testCase.user

			accessToken, refreshToken, _, err := testCase.token(tokenMaker, conf, user)

			registerResponse := testCase.registerResponse(user)

			arg := testCase.toCreateUserParams(registerRequest)

			testCase.buildStub(mockStore, user, accessToken, refreshToken, arg, registerRequest.Password)

			//resUser, resAccessToken, resRefreshToken, err := svc.RegisterService(context.Background(), registerRequest)
			resUser, _, _, err := svc.RegisterService(context.Background(), registerRequest)
			//res := ToRegisterResponse(resUser, resAccessToken, resRefreshToken)
			res := ToRegisterResponse(resUser)
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

	require.Equal(t, registerResponse.UserResponse.ID, res.UserResponse.ID)
	//require.Equal(t, registerResponse.TokenResponse.AccessToken, res.TokenResponse.AccessToken)
	//require.Equal(t, registerResponse.TokenResponse.RefreshToken, res.TokenResponse.RefreshToken)
	require.Equal(t, registerResponse.UserResponse.Name, res.UserResponse.Name)
	require.Equal(t, registerResponse.UserResponse.Email, res.UserResponse.Email)
	require.WithinDuration(t, registerResponse.UserResponse.CreatedAt, res.UserResponse.CreatedAt, time.Second)
	require.WithinDuration(t, registerResponse.UserResponse.UpdatedAt, res.UserResponse.UpdatedAt, time.Second)
}

func TestMeService(t *testing.T) {
	testCases := []struct {
		name          string
		svc           func(store *db.MockStore, hashPassword func(string) (string, error), checkPasswordHash func(string, string) error, tokenMaker token.Maker, config config.Config) *Service
		user          sqlc.User
		buildStub     func(store *db.MockStore, user sqlc.User)
		checkResponse func(t *testing.T, expect, got sqlc.User, err error)
	}{
		{
			name: "success",
			svc: func(store *db.MockStore, hashPassword func(string) (string, error), checkPasswordHash func(string, string) error, tokenMaker token.Maker, config config.Config) *Service {
				return NewService(store, hashPassword, checkPasswordHash, tokenMaker, config)
			},
			user: userfactory.NewOptions(nil),
			buildStub: func(store *db.MockStore, user sqlc.User) {
				store.EXPECT().GetUser(gomock.Any(), user.Email).Return(user, nil)
			},
			checkResponse: func(t *testing.T, expect, got sqlc.User, err error) {
				meServiceResponseChecker(t, expect, got, err)
			},
		},
		{
			name: "success",
			svc: func(store *db.MockStore, hashPassword func(string) (string, error), checkPasswordHash func(string, string) error, tokenMaker token.Maker, config config.Config) *Service {
				return NewService(store, hashPassword, checkPasswordHash, tokenMaker, config)
			},
			user: userfactory.NewOptions(nil),
			buildStub: func(store *db.MockStore, user sqlc.User) {
				store.EXPECT().GetUser(gomock.Any(), user.Email).Return(user, nil)
			},
			checkResponse: func(t *testing.T, expect, got sqlc.User, err error) {
				meServiceResponseChecker(t, expect, got, err)
			},
		},
		{
			name: "user not found",
			svc: func(store *db.MockStore, hashPassword func(string) (string, error), checkPasswordHash func(string, string) error, tokenMaker token.Maker, config config.Config) *Service {
				return NewService(store, hashPassword, checkPasswordHash, tokenMaker, config)
			},
			user: userfactory.NewOptions(nil),
			buildStub: func(store *db.MockStore, user sqlc.User) {
				store.EXPECT().GetUser(gomock.Any(), user.Email).Return(sqlc.User{}, sql.ErrNoRows)
			},
			checkResponse: func(t *testing.T, expect, got sqlc.User, err error) {
				fmt.Println(err)
				require.ErrorContains(t, err, "User is not found")
			},
		},
		{
			name: "failed to get user",
			svc: func(store *db.MockStore, hashPassword func(string) (string, error), checkPasswordHash func(string, string) error, tokenMaker token.Maker, config config.Config) *Service {
				return NewService(store, hashPassword, checkPasswordHash, tokenMaker, config)
			},
			user: userfactory.NewOptions(nil),
			buildStub: func(store *db.MockStore, user sqlc.User) {
				store.EXPECT().GetUser(gomock.Any(), user.Email).Return(sqlc.User{}, sql.ErrConnDone)
			},
			checkResponse: func(t *testing.T, expect, got sqlc.User, err error) {
				fmt.Println(err)
				require.ErrorContains(t, err, "Failed to get user")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := db.NewMockStore(ctrl)

			svc := testCase.svc(mockStore, util.HashPassword, util.CheckPasswordHash, tokenMaker, conf)

			testCase.buildStub(mockStore, testCase.user)

			user := testCase.user

			userRes, err := svc.MeService(context.Background(), user.Email)
			testCase.checkResponse(t, user, userRes, err)
		})
	}
}

func meServiceResponseChecker(t *testing.T, expect, got sqlc.User, err error) {
	require.NoError(t, err)
	require.Equal(t, expect.ID, got.ID)
	require.Equal(t, expect.Name, got.Name)
	require.Equal(t, expect.Email, got.Email)
	require.WithinDuration(t, expect.CreatedAt, got.CreatedAt, time.Second)
	require.WithinDuration(t, expect.UpdatedAt, got.UpdatedAt, time.Second)
}
