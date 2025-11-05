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
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/router"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

type Server struct {
	httpServer *http.Server
}

func NewServer(store db.Store, address, jwtSecretKey string) *Server {
	r := gin.Default()
	tokenMaker := util.NewTokenMaker(jwtSecretKey)
	router.SetupRouter(r, store, tokenMaker)

	srv := &http.Server{
		Addr:    address,
		Handler: r,
	}

	return &Server{httpServer: srv}
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

	log.Println("Server exited gracefully")
	return nil
}
