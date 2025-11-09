package userservice

import "github.com/hanifsyahsn/go_boilerplate/internal/db/sqlc"

func SqlcUserToUserResponse(user sqlc.User) UserResponse {
	return UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
