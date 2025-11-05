package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	_ "github.com/lib/pq"
)

type Store interface {
	sqlc.Querier
	RegisterTx(ctx context.Context, arg sqlc.CreateUserParams) (user sqlc.User, accessToken, refreshToken string, err error)
}

type SQLStore struct {
	*sqlc.Queries
	db     *sql.DB
	config config.Config
}

func NewSQLStore(config config.Config, conn *sql.DB) Store {
	return &SQLStore{
		Queries: sqlc.New(conn),
		db:      conn,
		config:  config,
	}
}

func (store *SQLStore) execTx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	q := sqlc.New(tx)
	if err := fn(q); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx err: %v, rollback err: %v", err, rbErr)
		}
		return err
	}

	return tx.Commit()
}
