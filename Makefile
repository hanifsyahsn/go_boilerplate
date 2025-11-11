migrate_up:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose up

migrate_up1:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose up 1

migrate_down:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose down

migrate_down1:
	migrate -path internal/db/migration -database "postgresql://postgres:12345@localhost:5432/go_boilerplate?sslmode=disable" -verbose down 1

create_db:
	docker exec -it go_boilerplate createdb -U postgres -O postgres go_boilerplate

drop_db:
	docker exec -it go_boilerplate dropdb -U postgres go_boilerplate

postgres:
	docker run --name go_boilerplate --network go_boilerplate-network -e POSTGRES_PASSWORD=12345 -e POSTGRES_USER=postgres -e POSTGRES_DB=go_boilerplate -p 5432:5432 -v go_boilerplate:/var/lib/postgresql/data -d postgres:9.6

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
	go test -v -count=1 -coverprofile=coverage.out ./...

coverage_report_view:
	go tool cover -html=coverage.out

server:
	go run ./cmd/api

mock:
	mockgen -source=internal/db/store.go -destination=internal/db/mock_store.go -package=db

DIRE ?= .
NAME ?= .

migrate_create:
	migrate create -ext sql -dir $(DIRE) -seq $(NAME)

test_package:
	go test -v -count=1 $(PACKAGE)

ec_private:
	openssl ecparam -name prime256v1 -genkey -noout -out internal/config/ec-private.pem

ec_public:
	openssl ec -in internal/config/ec-private.pem -pubout -out internal/config/ec-public.pem

build_docker:
	docker build -t go_boilerplate_service:latest .

container_docker:
	docker run --name go_boilerplate_service --network go_boilerplate-network -p 8080:8080 -e GIN_MODE=release -e DB_SOURCE="postgresql://postgres:12345@go_boilerplate:5432/go_boilerplate?sslmode=disable" go_boilerplate_service:latest

.PHONY: migrate_down, migrate_up, create_db, drop_db, postgres, db_start, db_stop, sqlc, test_only, test_coverage, server, mock, migrate_up1, migrate_down1, migrate_create, test_package, ec_private, ec_public, build_docker, container_docker