package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/handler/authhandler"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware"
	"github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

func SetupRouter(r *gin.Engine, store db.Store, tokenMaker *util.TokenMaker) {
	r.Use(middleware.CORSMiddleware())

	authService := authservice.NewService(store, util.HashPassword, util.CheckPasswordHash, tokenMaker)
	authHandler := authhandler.NewHandler(store, authService)

	auth := r.Group("/auth")
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)

	authProtected := auth.Group("/")
	authProtected.Use(middleware.AuthMiddleware(tokenMaker))
	authProtected.Use(middleware.RateLimitMiddleware())
	authProtected.POST("/logout", authHandler.Logout)
	authProtected.POST("/refresh", authHandler.RefreshAccessToken)
}
