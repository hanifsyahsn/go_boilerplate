package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/handler/authhandler"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware"
	"github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

func SetupRouter(r *gin.Engine, store db.Store, tokenMaker token.Maker, config config.Config) {
	r.Use(middleware.CORSMiddleware())

	authService := authservice.NewService(store, util.HashPassword, util.CheckPasswordHash, tokenMaker, config)
	authHandler := authhandler.NewHandler(store, authService)

	auth := r.Group("/auth")
	auth.Use(middleware.RateLimitIpMiddleware())
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)

	authProtected := auth.Group("/")
	authProtected.Use(middleware.AuthMiddleware(tokenMaker))
	authProtected.Use(middleware.RateLimitUserMiddleware())
	authProtected.POST("/logout", authHandler.Logout)
	authProtected.POST("/refresh", authHandler.RefreshAccessToken)
}
