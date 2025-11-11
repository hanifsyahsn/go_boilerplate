# go app gets compiled into a binary
FROM golang:1.25.3-alpine3.22 AS builder
# sets the working directory inside the container to /app
WORKDIR /app
# copies everything from project
COPY . .
# compiles go app
# -o main -> output binary named main
# ./cmd/api -> project entry point
RUN go build -o main ./cmd/api
# after this, the builder image now has a compiled binary file at /app/main

# starts a new container from the plain Alpine Linux 3.22 image
# this container doesn’t have go or any build tools, only what is needed to run the binary
FROM alpine:3.22
# sets /app as the working directory for this runtime container
WORKDIR /app
# copies the compiled binary (/app/main) from the builder stage -> into the current container’s /app directory
COPY --from=builder /app/main .
# copies local app.env file
# for prod image publish must remove this
COPY app.env .
# for prod image publish please must this
COPY ./internal/config/ec-private.pem ./internal/config/ec-private.pem
# for prod image publish please must this
COPY ./internal/config/ec-public.pem ./internal/config/ec-public.pem

# declares that the app listens on port 8080 inside the container
EXPOSE 8080
# defines what command should run by default when the container starts
ENTRYPOINT ["/app/main"]