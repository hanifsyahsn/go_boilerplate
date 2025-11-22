# ---------- BUILD STAGE ----------
FROM golang:1.25.3-alpine3.22 AS builder

WORKDIR /app

# Cache go modules first (faster CI)
COPY go.mod go.sum ./
RUN go mod download

# Copy app source
COPY . .

# Build statically for minimal Alpine image
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o main ./cmd/api


# ---------- RUNTIME STAGE ----------
FROM alpine:3.22

WORKDIR /app

# Install certificates in case app calls HTTPS APIs
RUN apk --no-cache add ca-certificates

# Copy already built binary from CI
COPY main .

# ===== IMPORTANT =====
COPY app.env .
COPY ./internal/config/ec-private.pem ./internal/config/ec-private.pem
COPY ./internal/config/ec-public.pem ./internal/config/ec-public.pem
# =====================

EXPOSE 8080

ENTRYPOINT ["./main"]
