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
