package token

import (
	"log"
	"os"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
)

var conf config.Config

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../../..")
	if err != nil {
		log.Fatalf("Cannot load config: %v", err)
	}

	code := m.Run()
	os.Exit(code)
}
