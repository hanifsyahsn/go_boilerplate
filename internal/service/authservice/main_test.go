package authservice

import (
	"log"
	"os"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	"github.com/hanifsyahsn/go_boilerplate/internal/util"
)

var conf config.Config
var tokenMaker *util.TokenMaker

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../../..")
	if err != nil {
		log.Fatal("Cannot load config: ", err)
	}

	tokenMaker = util.NewTokenMaker(conf.JWTSecretKey)

	code := m.Run()
	os.Exit(code)
}
