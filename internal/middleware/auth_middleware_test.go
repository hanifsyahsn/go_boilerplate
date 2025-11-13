package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/factory/userfactory"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
	"github.com/stretchr/testify/require"
)

func addAuthorization(
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

func TestAuthMiddleware(t *testing.T) {
	testCases := []struct {
		name          string
		user          sqlc.User
		setupAuth     func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User)
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "OK",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAuthorization(t, request, tokenMaker, authorizationTypeBearer, user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			name: "No Authorization",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name: "Unsupported Authorization",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAuthorization(t, request, tokenMaker, "unsupported", user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name: "Invalid Authorization Format",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAuthorization(t, request, tokenMaker, "", user, time.Duration(0))
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name: "Expired Token",
			user: userfactory.NewOptions(nil),
			setupAuth: func(t *testing.T, request *http.Request, tokenMaker token.Maker, user sqlc.User) {
				addAuthorization(t, request, tokenMaker, authorizationTypeBearer, user, -time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			router := gin.New()

			router.GET("/auth", AuthMiddleware(tokenMaker), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{})
			})

			recorder := httptest.NewRecorder()
			request, err := http.NewRequest(http.MethodGet, "/auth", nil)
			require.NoError(t, err)

			user := tc.user

			tc.setupAuth(t, request, tokenMaker, user)
			router.ServeHTTP(recorder, request)
			tc.checkResponse(t, recorder)
		})
	}
}
