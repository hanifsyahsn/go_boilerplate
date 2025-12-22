package authservice

import (
	"context"
	"database/sql"
	ierr "errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/constant"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/redis"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
	"github.com/lib/pq"
	redisClient "github.com/redis/go-redis/v9"
)

type Service struct {
	store         db.Store
	hashPassword  func(password string) (string, error)
	checkPassword func(password, hash string) error
	tokenMaker    token.Maker
	config        config.Config
	redis         redis.Client
}

func NewService(
	store db.Store,
	hashFunc func(string) (string, error),
	checkPassword func(password, hash string) error,
	tokenMaker token.Maker,
	config config.Config,
	redis redis.Client,
) *Service {
	return &Service{store: store, hashPassword: hashFunc, checkPassword: checkPassword, tokenMaker: tokenMaker, config: config, redis: redis}
}

func (service *Service) RegisterService(context context.Context, request RegisterRequest) (user sqlc.User, accessToken, refreshToken string, errs error) {
	var err error
	request.Password, err = service.hashPassword(request.Password)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to process user password", err)
		return
	}

	arg := ToCreateUserParams(request)

	user, accessToken, refreshToken, accessClaims, _, err := service.store.RegisterTx(context, arg)
	if err != nil {
		var pqErr *pq.Error
		if ierr.As(err, &pqErr) {
			if pqErr.Code.Name() == "unique_violation" {
				if strings.Contains(pqErr.Constraint, "users_email_unique") {
					errs = errors.New(errors.CodeConflict, "Email already exists", err)
					return
				}
			}
		}
		errs = errors.New(errors.CodeInternal, "Failed to register user", err)
		return
	}

	err = service.setJti(accessClaims, user.ID)
	if err != nil {
		errs = err
		return
	}

	return
}

func (service *Service) LoginService(context context.Context, request LoginRequest) (user sqlc.User, accessToken, refreshToken string, errs error) {
	user, err := service.store.GetUser(context, request.Email)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New(errors.CodeNotFound, "User is not found", err)
			return
		}
		errs = errors.New(errors.CodeInternal, "Failed to get user", err)
		return
	}

	err = service.checkPassword(request.Password, user.Password)
	if err != nil {
		errs = errors.New(errors.CodeUnauthorized, "Wrong Password", err)
		return
	}

	accessToken, refreshToken, accessClaims, refreshClaims, err := service.tokenMaker.CreateToken(user, service.config.AccessTokenDuration, service.config.RefreshTokenDuration)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to login user", err)
		return
	}

	refreshTokenExp, ok := refreshClaims[constant.ExpirationKey].(int64)
	if !ok {
		errs = errors.New(errors.CodeInternal, "Failed to login user", fmt.Errorf("token expiration is not an integer"))
		return
	}
	expiresAt := time.Unix(refreshTokenExp, 0)

	upsertRefreshTokenParams := ToUpsertRefreshTokenParams(user.ID, token.HashToken(refreshToken), expiresAt)

	_, err = service.store.UpsertRefreshToken(context, upsertRefreshTokenParams)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to login user", err)
		return
	}

	userKey := "user:access:" + strconv.Itoa(int(user.ID))

	err = service.redis.Del(userKey)
	if err != nil && !ierr.Is(err, redisClient.Nil) {
		errs = errors.New(errors.CodeInternal, "Failed to login user", err)
		return
	}

	err = service.setJti(accessClaims, user.ID)
	if err != nil {
		errs = err
		return
	}

	return
}

func (service *Service) setJti(accessClaims jwt.MapClaims, userID int64) (errs error) {
	jti, ok := accessClaims[constant.JsonWebTokenIdKey].(string)
	if !ok {
		errs = errors.New(errors.CodeInternal, "Failed to register user", fmt.Errorf("JSON web token ID is not a string"))
		return
	}

	expUnix, ok := accessClaims[constant.ExpirationKey].(int64)
	if !ok {
		errs = errors.New(errors.CodeInternal, "Failed to register user", fmt.Errorf("token expiration is not an integer"))
		return
	}
	expiresAt := time.Unix(expUnix, 0)
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	key := "user:access:" + strconv.Itoa(int(userID))

	err := service.redis.Set(key, jti, ttl)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to register user", err)
		return
	}
	return nil
}

func (service *Service) LogoutService(context context.Context, refreshToken string, userId int64) (errs error) {
	hashedToken := token.HashToken(refreshToken)
	arg := ToGetRefreshTokenByUserIdParams(hashedToken, userId)
	_, err := service.store.GetRefreshTokenByUserId(context, arg)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New(errors.CodeNotFound, "Failed to logout user", err)
			return
		}
		errs = errors.New(errors.CodeInternal, "Failed to logout user", err)
		return
	}

	err = service.store.DeleteRefreshToken(context, hashedToken)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to logout user", err)
		return
	}

	userKey := "user:access:" + strconv.Itoa(int(userId))

	err = service.redis.Del(userKey)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to logout user", err)
		return
	}

	return
}

func (service *Service) RefreshAccessTokenService(context context.Context, refreshToken, email string, userId int64, jti string) (accessToken, refreshTokenR string, errs error) {
	hashedToken := token.HashToken(refreshToken)
	arg := ToGetRefreshTokenByUserIdParams(hashedToken, userId)
	_, err := service.store.GetRefreshTokenByUserId(context, arg)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New(errors.CodeNotFound, "Failed to refresh token", err)
			return
		}
		errs = errors.New(errors.CodeInternal, "Failed to refresh token", err)
		return
	}

	accessToken, err = service.tokenMaker.RefreshToken(email, userId, service.config.AccessTokenDuration, jti)
	if err != nil {
		errs = errors.New(errors.CodeInternal, "Failed to refresh token", err)
		return
	}

	refreshTokenR = refreshToken
	return
}

func (service *Service) MeService(context context.Context, email string) (user sqlc.User, errs error) {
	user, err := service.store.GetUser(context, email)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New(errors.CodeNotFound, "User is not found", err)
			return
		}
		errs = errors.New(errors.CodeInternal, "Failed to get user", err)
		return
	}
	return
}
