# ---------- RUNTIME STAGE ----------
FROM alpine:3.22

WORKDIR /app

# Install certificates in case app calls HTTPS APIs
RUN apk --no-cache add ca-certificates

# Copy already built binary from CI
COPY main .

EXPOSE 8080

ENTRYPOINT ["./main"]
