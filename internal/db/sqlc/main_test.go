package sqlc

import (
	"database/sql"
	"log"
	"os"
	"testing"

	"github.com/hanifsyahsn/go_boilerplate/internal/config"
	_ "github.com/lib/pq"
)

var testQueries *Queries
var testDB *sql.DB
var conf config.Config

func TestMain(m *testing.M) {
	var err error
	conf, err = config.LoadConfig("../../..")
	if err != nil {
		log.Fatal("Cannot load config: ", err)
	}

	testDB, err = sql.Open(conf.DBDriver, conf.DBSource)
	if err != nil {
		log.Fatal("Cannot open DB driver:", err)
	}

	if err = testDB.Ping(); err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	testQueries = New(testDB)

	code := m.Run()

	err = testDB.Close()
	if err != nil {
		log.Fatal("Cannot close database connection: ", err)
	}

	os.Exit(code)
}
