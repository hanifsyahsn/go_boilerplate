package userfactory

import (
	"fmt"
	"time"

	"github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

type Options struct {
	ID        int64
	Email     string
	Name      string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewOptions(opts *Options) sqlc.User {
	if opts == nil {
		opts = &Options{}
	}

	user := sqlc.User{
		ID:        opts.ID,
		Email:     opts.Email,
		Name:      opts.Name,
		Password:  opts.Password,
		CreatedAt: opts.CreatedAt,
		UpdatedAt: opts.UpdatedAt,
	}

	if user.ID == 0 {
		user.ID = 1
	}
	if user.Email == "" {
		user.Email = fmt.Sprintf("%s@mail.com", util.RandomString(6))
	}
	if user.Name == "" {
		user.Name = util.RandomString(6)
	}
	if user.Password == "" {
		user.Password = util.RandomString(6)
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now()
	}

	return user
}
