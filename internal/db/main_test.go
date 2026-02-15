package db

import (
	"crypto/ecdsa"
	"database/sql"
	"log"
	"os"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

// var testQueries *sqlc.Queries
var testDB *sql.DB
var conf config.Config
var tokenMaker token.Maker

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../..")
	if err != nil {
		log.Fatal("Cannot load config: ", err)
	}

	if err = conf.Validate(); err != nil {
		log.Fatal("Invalid configuration:", err)
	}

	testDB, err = sql.Open(conf.DBDriver, conf.DBSource)
	if err != nil {
		log.Fatal("Cannot open DB driver:", err)
	}

	if err = testDB.Ping(); err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	//noinspection DuplicatedCode
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

	code := m.Run()

	err = testDB.Close()
	if err != nil {
		log.Fatal("Cannot close database connection: ", err)
	}

	os.Exit(code)
}
