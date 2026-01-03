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

LABEL org.opencontainers.image.title="IONOS-DDNS-Go"
LABEL org.opencontainers.image.description="Leichtgewichtiger DynDNS-Client für IONOS mit Dual-Stack Support"
LABEL org.opencontainers.image.authors="CrazyUs3r"
LABEL org.opencontainers.image.source="https://github.com/CrazyUs3r/IONOS-DDNS"
LABEL org.opencontainers.image.version="1.1"

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app

# User und Verzeichnisse für JSON-Logs
RUN addgroup -S dyndns && adduser -S dyndns -G dyndns && \
    mkdir -p /logs && chown dyndns:dyndns /logs

COPY --from=builder --chown=dyndns:dyndns /app/dyndns .

USER dyndns
VOLUME ["/logs"]

HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./dyndns"]
