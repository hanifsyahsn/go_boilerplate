package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/handler/authhandler"
	"github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

func SetupRouter(r *gin.Engine, store db.Store, tokenMaker *util.TokenMaker) {
	authService := authservice.NewService(store, util.HashPassword, util.CheckPasswordHash, tokenMaker)
	authHandler := authhandler.NewHandler(store, authService)

	auth := r.Group("/auth")
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)
}
