package main

import (
	"database/sql"
	"log"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/server"
)

func main() {
	conf, err := config.LoadConfig(".")
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	conn, err := sql.Open(conf.DBDriver, conf.DBSource)
	if err != nil {
		log.Fatal("Cannot connect to database")
	}

	store := db.NewSQLStore(conf, conn)
	srv := server.NewServer(store, conf.ServerAddress, conf.JWTSecretKey)

	if err = srv.Run(); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
