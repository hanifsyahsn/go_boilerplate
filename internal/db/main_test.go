package db

import (
	"database/sql"
	"log"
	"os"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
)

// var testQueries *sqlc.Queries
var testDB *sql.DB
var conf config.Config

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../..")
	if err != nil {
		log.Fatal("Cannot load config: ", err)
	}
	//
	testDB, err = sql.Open(conf.DBDriver, conf.DBSource)
	if err != nil {
		log.Fatal("Cannot connect to database: ", err)
	}

	//testQueries = sqlc.New(testDB)

	code := m.Run()

	//err = testDB.Close()
	//if err != nil {
	//	log.Fatal("Cannot close database connection: ", err)
	//}

	os.Exit(code)
}
