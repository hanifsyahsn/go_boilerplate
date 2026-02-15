package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	autHandler "github.com/hanifsyahsn/go_boilerplate/internal/handler/authhandler"
	authMiddleware "github.com/hanifsyahsn/go_boilerplate/internal/middleware/auth"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware/cors"
	"github.com/hanifsyahsn/go_boilerplate/internal/middleware/limiter"
	authService "github.com/hanifsyahsn/go_boilerplate/internal/service/authservice"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/redis"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

func SetupRouter(r *gin.Engine, store db.Store, tokenMaker token.Maker, config config.Config, redis redis.Client) {
	gin.SetMode(config.GinMode)
	r.Use(cors.CORSMiddleware())

	authSvc := authService.NewService(store, util.HashPassword, util.CheckPasswordHash, tokenMaker, config, redis)
	authHandler := autHandler.NewHandler(store, authSvc)

	auth := r.Group("/auth")
	auth.Use(limiter.RateLimitIpMiddleware())
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)

	authAccessProtected := auth.Group("/")
	authAccessProtected.Use(authMiddleware.AccessAuthMiddleware(tokenMaker, redis))
	authAccessProtected.Use(limiter.RateLimitUserMiddleware())
	authAccessProtected.GET("/me", authHandler.Me)

	authRefreshProtected := auth.Group("/")
	authRefreshProtected.Use(authMiddleware.RefreshAuthMiddleware(tokenMaker))
	authRefreshProtected.Use(limiter.RateLimitUserMiddleware())
	authRefreshProtected.POST("/logout", authHandler.Logout)
	authRefreshProtected.POST("/refresh", authHandler.RefreshAccessToken)
}
