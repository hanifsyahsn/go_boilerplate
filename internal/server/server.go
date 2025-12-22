package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/router"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/redis"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
	goRedis "github.com/redis/go-redis/v9"
)

type Server struct {
	// We use this to have our graceful shutdown since gin doesn't have a stop / shutdown method
	httpServer *http.Server
	redis      redis.Client
}

func NewServer(store db.Store, address string, tokenMaker token.Maker, config config.Config) *Server {
	goRedisClient := goRedis.NewClient(&goRedis.Options{
		Addr:     config.RedisAddress,
		Password: config.RedisPassword,
		DB:       0,
	})

	if _, err := goRedisClient.Ping(context.Background()).Result(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	redisClient := redis.NewRedisClient(goRedisClient)

	r := gin.Default()
	router.SetupRouter(r, store, tokenMaker, config, redisClient)

	srv := &http.Server{
		Addr:    address,
		Handler: r,
	}

	return &Server{
		httpServer: srv,
		redis:      redisClient,
	}
}

func (server *Server) Run() error {

	go func() {
		log.Printf("Server running on %s", server.httpServer.Addr)
		if err := server.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.httpServer.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	if err := server.redis.Close(); err != nil {
		log.Println("Error closing Redis:", err)
	}

	log.Println("Server exited gracefully")
	return nil
}
