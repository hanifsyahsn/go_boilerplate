migrate_up:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose up

migrate_down:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose down

create_db:
	docker exec -it go_boilerplate createdb -U postgres -O postgres go_boilerplate

drop_db:
	docker exec -it go_boilerplate dropdb -U postgres go_boilerplate

postgres:
	docker run --name go_boilerplate -e POSTGRES_PASSWORD=12345 -e POSTGRES_USER=postgres -e POSTGRES_DB=go_boilerplate -p 5432:5432 -v go_boilerplate:/var/lib/postgresql/data -d postgres:9.6

db_start:
	docker start go_boilerplate

db_stop:
	docker stop go_boilerplate

sqlc:
	sqlc generate

TEST ?= .
PKG ?= ./db/sqlc

test_only:
	go test -v -run ^$(TEST)$$ $(PKG) -count=1

test_coverage:
	go test -v -coverprofile=coverage.out ./...

coverage_report_view:
	go tool cover -html=coverage.out

server:
	go run ./cmd/api

mock:
	mockgen -source=internal/db/store.go -destination=internal/db/mock_store.go -package=db

.PHONY: migrate_down, migrate_up, create_db, drop_db, postgres, db_start, db_stop, sqlc, test_only, test_coverage, server, mock