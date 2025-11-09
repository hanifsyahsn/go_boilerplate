package middleware

import (
	"crypto/ecdsa"
	"log"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/util/token"
)

var conf config.Config
var tokenMaker token.Maker

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../..")
	if err != nil {
		log.Fatal("Cannot load config: ", err)
	}

	if conf.JWTHS256 {
		tokenMaker = token.NewTokenMakerHS256(conf.JWTSecretKey, conf.ENV)
	} else if conf.JWTES256 {
		var privateKey *ecdsa.PrivateKey
		privateKey, err = token.LoadECPrivateKey("../../internal/config/ec-private.pem")
		if err != nil {
			log.Fatal("Error loading private key")
		}

		var publicKey *ecdsa.PublicKey
		publicKey, err = token.LoadECPublicKey("../../internal/config/ec-public.pem")
		if err != nil {
			log.Fatal("Error loading public key")
		}

		tokenMaker = token.NewTokenMakerES256(privateKey, publicKey, conf.ENV)
	} else {
		log.Fatal("Unsupported JWT")
	}

	gin.SetMode(gin.TestMode)

	code := m.Run()
	os.Exit(code)
}
