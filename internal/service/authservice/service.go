package authservice

import (
	"context"
	"database/sql"
	ierr "errors"
	"net/http"
	"strings"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/errors"
	"github.com/lib/pq"
)

type Service struct {
	store         db.Store
	hashPassword  func(password string) (string, error)
	checkPassword func(password, hash string) error
	tokenMaker    *util.TokenMaker
}

func NewService(
	store db.Store,
	hashFunc func(string) (string, error),
	checkPassword func(password, hash string) error,
	tokenMaker *util.TokenMaker,
) *Service {
	if hashFunc == nil {
		hashFunc = util.HashPassword
	}
	if checkPassword == nil {
		checkPassword = util.CheckPasswordHash
	}
	return &Service{store: store, hashPassword: hashFunc, checkPassword: checkPassword, tokenMaker: tokenMaker}
}

func (service *Service) RegisterService(context context.Context, request RegisterRequest) (user sqlc.User, accessToken, refreshToken string, errs error) {
	var err error
	request.Password, err = service.hashPassword(request.Password)
	if err != nil {
		errs = errors.New("Failed to process password", http.StatusInternalServerError, err)
		return
	}

	arg := ToCreateUserParams(request)

	user, accessToken, refreshToken, err = service.store.RegisterTx(context, arg)
	if err != nil {
		var pqErr *pq.Error
		if ierr.As(err, &pqErr) {
			if pqErr.Code.Name() == "unique_violation" {
				if strings.Contains(pqErr.Constraint, "users_email_unique") {
					errs = errors.New("Email already exists", http.StatusBadRequest, err)
					return
				}
			}
		}
		errs = errors.New("Failed to register user", http.StatusInternalServerError, err)
		return
	}

	return
}

func (service *Service) LoginService(context context.Context, request LoginRequest) (user sqlc.User, accessToken, refreshToken string, errs error) {
	user, err := service.store.GetUser(context, request.Email)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New("User is not found", http.StatusNotFound, err)
			return
		}
		errs = errors.New("failed to get user", http.StatusInternalServerError, err)
		return
	}

	err = service.checkPassword(request.Password, user.Password)
	if err != nil {
		errs = errors.New("wrong password", http.StatusInternalServerError, err)
		return
	}

	accessToken, refreshToken, refreshTokenExp, err := service.tokenMaker.CreateToken(user.Email)
	if err != nil {
		errs = errors.New("failed to generate token", http.StatusInternalServerError, err)
		return
	}

	upsertRefreshTokenParams := ToUpsertRefreshTokenParams(user.ID, refreshToken, refreshTokenExp)

	_, err = service.store.UpsertRefreshToken(context, upsertRefreshTokenParams)
	if err != nil {
		errs = errors.New("failed to upsert refresh token", http.StatusInternalServerError, err)
		return
	}

	return user, accessToken, refreshToken, errs
}

func (service *Service) LogoutService(context context.Context, refreshToken string) (errs error) {
	_, err := service.store.GetRefreshToken(context, refreshToken)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New("Refresh token is not found", http.StatusNotFound, err)
			return
		}
		errs = errors.New("Failed to get refresh token", http.StatusInternalServerError, err)
		return
	}

	err = service.store.DeleteRefreshToken(context, refreshToken)
	if err != nil {
		errs = errors.New("Failed to delete refresh token", http.StatusInternalServerError, err)
		return
	}
	return
}

func (service *Service) RefreshAccessTokenService(context context.Context, refreshToken, email string) (accessToken, refreshTokenR string, refreshTokenExpiration time.Time, errs error) {
	refreshTokenData, err := service.store.GetRefreshToken(context, refreshToken)
	if err != nil {
		if ierr.Is(err, sql.ErrNoRows) {
			errs = errors.New("Refresh token is not found", http.StatusNotFound, err)
			return
		}
		errs = errors.New("failed to get refresh token data", http.StatusInternalServerError, err)
		return
	}

	accessToken, err = service.tokenMaker.RefreshToken(email)
	if err != nil {
		errs = errors.New("failed to generate access token", http.StatusInternalServerError, err)
		return
	}

	refreshTokenR = refreshTokenData.RefreshToken
	refreshTokenExpiration = refreshTokenData.ExpiredAt
	return
}
