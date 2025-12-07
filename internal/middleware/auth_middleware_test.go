package middleware

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/factory/userfactory"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
	mockmaker "github.com/hanifsyahsn/go_boilerplate/internal/util/token/mock"
	"github.com/stretchr/testify/require"
)

func addAccessAuthorizationCookie(
	t *testing.T,
	request *http.Request,
	tokenMaker token.Maker,
	user sqlc.User,
	duration time.Duration,
) {
	var dur time.Duration
	if duration != time.Duration(0) {
		dur = duration
	} else {
		dur = conf.AccessTokenDuration
	}
	accessToken, refreshToken, refreshTokenExpiration, err := tokenMaker.CreateToken(user, dur, conf.RefreshTokenDuration)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)

	request.AddCookie(&http.Cookie{
		Name:     constant.AccessTokenKey,
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(15 * time.Minute),
		MaxAge:   60 * 15,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func addAccessAuthorizationHeader(
	t *testing.T,
	request *http.Request,
	tokenMaker token.Maker,
	authorizationType string,
	user sqlc.User,
	duration time.Duration,
) {
	var dur time.Duration
	if duration != time.Duration(0) {
		dur = duration
	} else {
		dur = conf.AccessTokenDuration
	}
	accessToken, refreshToken, refreshTokenExpiration, err := tokenMaker.CreateToken(user, dur, conf.RefreshTokenDuration)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)

	authorizationHeader := fmt.Sprintf("%s %s", authorizationType, accessToken)
	request.Header.Add(authorizationHeaderKey, authorizationHeader)
}

func TestAccessAuthMiddleware(t *testing.T) {
	testCases := []struct {
		name          string
		user          sqlc.User
		setupAuth     func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User)
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
		useMockToken  bool
	}{
		{
			name: "OK",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationCookie(t, request, tokenMaker, user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "No Token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Expired Token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationCookie(t, request, tokenMaker, user, -time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to get access token from header when the token is missing from cookie",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationHeader(t, request, tokenMaker, authorizationTypeBearer, user, time.Duration(math.MaxInt64))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to throw an error when authorization header format is invalid",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationHeader(t, request, tokenMaker, "", user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to throw an error when email is not found inside the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        float64(user.ID),
							constant.ExpirationKey: float64(10988454472),
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when email is not a string from the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        float64(user.ID),
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      int64(1),
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when sub is not found in the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      user.Email,
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when sub is an invalid type",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        "1",
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      user.Email,
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			router := gin.New()

			var tm token.Maker
			if tc.useMockToken {
				tm = mockmaker.NewMockMaker(ctrl)
			} else {
				tm = tokenMaker
			}

			router.GET("/auth", AccessAuthMiddleware(tm), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{})
			})

			recorder := httptest.NewRecorder()
			request, err := http.NewRequest(http.MethodGet, "/auth", nil)
			require.NoError(t, err)

			user := tc.user

			tc.setupAuth(t, request, tm, user)
			router.ServeHTTP(recorder, request)
			tc.checkResponse(t, recorder)
		})
	}
}

func addRefreshAuthorization(
	t *testing.T,
	request *http.Request,
	tokenMaker token.Maker,
	user sqlc.User,
	duration time.Duration,
) {
	var dur time.Duration
	if duration != time.Duration(0) {
		dur = duration
	} else {
		dur = conf.RefreshTokenDuration
	}
	accessToken, refreshToken, refreshTokenExpiration, err := tokenMaker.CreateToken(user, conf.AccessTokenDuration, dur)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, refreshTokenExpiration)

	request.AddCookie(&http.Cookie{
		Name:     constant.RefreshTokenKey,
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		MaxAge:   60 * 60 * 24 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func TestRefreshAuthMiddleware(t *testing.T) {
	testCases := []struct {
		name          string
		user          sqlc.User
		setupAuth     func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User)
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
		useMockToken  bool
	}{
		{
			name: "OK",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addRefreshAuthorization(t, request, tokenMaker, user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "No Token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Expired Token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addRefreshAuthorization(t, request, tokenMaker, user, -time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to get access token from header when the token is missing from cookie",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationHeader(t, request, tokenMaker, authorizationTypeBearer, user, time.Duration(math.MaxInt64))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to throw an error when authorization header format is invalid",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAccessAuthorizationHeader(t, request, tokenMaker, "", user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: false,
		},
		{
			name: "Be able to throw an error when email is not found x inside the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        float64(user.ID),
							constant.ExpirationKey: float64(10988454472),
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when email is not a string from the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        float64(user.ID),
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      int64(1),
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when sub is not found in the token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      user.Email,
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
		{
			name: "Be able to throw an error when sub is an invalid type",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				request.Header.Add(authorizationHeaderKey, fmt.Sprintf("%s sometoken", authorizationTypeBearer))
				mock := tokenMaker.(*mockmaker.MockMaker)
				mock.EXPECT().
					VerifyToken("sometoken").
					Return(&jwt.Token{},
						map[string]interface{}{
							constant.SubKey:        "1",
							constant.ExpirationKey: float64(10988454472),
							constant.EmailKey:      user.Email,
							constant.IssuedAtKey:   float64(1765082435),
							constant.IssuerKey:     conf.TokenIssuer,
						}, nil)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
			useMockToken: true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			router := gin.New()

			var tm token.Maker
			if tc.useMockToken {
				tm = mockmaker.NewMockMaker(ctrl)
			} else {
				tm = tokenMaker
			}

			router.GET("/auth", RefreshAuthMiddleware(tm), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{})
			})

			recorder := httptest.NewRecorder()
			request, err := http.NewRequest(http.MethodGet, "/auth", nil)
			require.NoError(t, err)

			user := tc.user

			tc.setupAuth(t, request, tm, user)
			router.ServeHTTP(recorder, request)
			tc.checkResponse(t, recorder)
		})
	}
}
