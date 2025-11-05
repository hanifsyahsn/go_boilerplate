package authservice

import (
	"context"
	ierr "errors"
	"log"
	"net/http"
	"strings"

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
		log.Println("Error Hash Password: ", err)
		errs = errors.New("failed to process password", http.StatusInternalServerError)
		return
	}

	arg := ToCreateUserParams(request)

	user, accessToken, refreshToken, err = service.store.RegisterTx(context, arg)
	if err != nil {
		var pqErr *pq.Error
		if ierr.As(err, &pqErr) {
			if pqErr.Code.Name() == "unique_violation" {
				if strings.Contains(pqErr.Constraint, "users_email_unique") {
					log.Println("Unique Violation: ", err)
					errs = errors.New("email already exists", http.StatusBadRequest)
					return
				}
			}
		}
		log.Println("Failed to register user: ", err)
		errs = errors.New("failed to register user", http.StatusInternalServerError)
		return
	}

	return
}

func (service *Service) LoginService(context context.Context, request LoginRequest) (user sqlc.User, accessToken, refreshToken string, errs error) {
	user, err := service.store.GetUser(context, request.Email)
	if err != nil {
		log.Println("Failed to get user: ", err)
		errs = errors.New("failed to get user", http.StatusInternalServerError)
		return
	}

	hashedPassword, err := service.hashPassword(request.Password)
	if err != nil {
		log.Println("Error Hash Password: ", err)
		errs = errors.New("failed to process password", http.StatusInternalServerError)
		return
	}

	err = service.checkPassword(request.Password, hashedPassword)
	if err != nil {
		log.Println("Password is wrong: ", err)
		errs = errors.New("failed to process password", http.StatusInternalServerError)
		return
	}

	accessToken, refreshToken, refreshTokenExp, err := service.tokenMaker.CreateToken(user.Email)
	if err != nil {
		log.Println("Failed to generate token: ", err)
		errs = errors.New("failed to generate token", http.StatusInternalServerError)
		return
	}

	upsertRefreshTokenParams := ToUpsertRefreshTokenParams(user.ID, refreshToken, refreshTokenExp)

	_, err = service.store.UpsertRefreshToken(context, upsertRefreshTokenParams)
	if err != nil {
		log.Println("Failed to upsert refresh token: ", err)
		errs = errors.New("failed to upsert refresh token", http.StatusInternalServerError)
		return
	}

	return user, accessToken, refreshToken, errs
}
