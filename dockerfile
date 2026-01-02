# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go mod init dyndns && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o dyndns main.go

ENV DOMAINS="example.com" \
    TZ=Europe/Berlin \
    IP_MODE="BOTH" \
    INTERFACE="eth0" \
    INTERVAL=300


# Stage 2: Final Image
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app

# User und Verzeichnisse für JSON-Logs
RUN addgroup -S dyndns && adduser -S dyndns -G dyndns && \
    mkdir -p /logs && chown dyndns:dyndns /logs

COPY --from=builder --chown=dyndns:dyndns /app/dyndns .

USER dyndns
VOLUME ["/logs"]

# Healthcheck auf Port 8080
HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./dyndns"]
