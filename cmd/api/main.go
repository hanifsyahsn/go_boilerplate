package main

import (
	"crypto/ecdsa"
	"database/sql"
	"log"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/db"
	"github.com/hanifsyahsn/go_boilerplate/internal/server"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

func main() {
	conf, err := config.LoadConfig(".")
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	if err = conf.Validate(); err != nil {
		log.Fatal("Invalid configuration:", err)
	}

	conn, err := sql.Open(conf.DBDriver, conf.DBSource)
	if err != nil {
		log.Fatal("Cannot open DB driver:", err)
	}

	if err = conn.Ping(); err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	var tokenMaker token.Maker

	if conf.JWTHS256 {
		tokenMaker = token.NewTokenMakerHS256(conf.JWTSecretKey, conf.TokenIssuer)
	} else if conf.JWTES256 {
		var privateKey *ecdsa.PrivateKey
		privateKey, err = token.LoadECPrivateKey(conf.ECPrivateKeyPath)
		if err != nil {
			log.Fatal("Error loading private key")
		}

		var publicKey *ecdsa.PublicKey
		publicKey, err = token.LoadECPublicKey(conf.ECPublicKeyPath)
		if err != nil {
			log.Fatal("Error loading public key")
		}

		tokenMaker = token.NewTokenMakerES256(privateKey, publicKey, conf.TokenIssuer)
	} else {
		log.Fatal("Unsupported JWT")
	}

	store := db.NewSQLStore(conf, conn, tokenMaker)
	srv := server.NewServer(store, conf.ServerAddress, tokenMaker, conf)

	if err = srv.Run(); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
