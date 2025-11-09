package db

import (
	"context"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
)

func (store *SQLStore) RegisterTx(ctx context.Context, arg sqlc.CreateUserParams) (user sqlc.User, accessToken, refreshToken string, err error) {
	err = store.execTx(ctx, func(q *sqlc.Queries) error {
		var txErr error
		user, txErr = q.CreateUser(ctx, arg)
		if txErr != nil {
			return txErr
		}

		var refreshTokenExp time.Time
		accessToken, refreshToken, refreshTokenExp, txErr = store.tokenMaker.CreateToken(user.Email, store.config.AccessTokenDuration, store.config.RefreshTokenDuration)
		if txErr != nil {
			return txErr
		}

		_, txErr = q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
			UserID:       user.ID,
			RefreshToken: refreshToken,
			ExpiredAt:    refreshTokenExp,
		})

		return txErr
	})

	return
}
